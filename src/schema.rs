use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest as ShaDigest, Sha256};
use wasm_bindgen::prelude::*;

const DEFAULT_SCHEMA_ID: &str = "dynamic-credential";
const DEFAULT_SCHEMA_VERSION: &str = "1.0.0";

type SchemaResult<T> = Result<T, String>;

// `wasm-bindgen` cannot derive structural TypeScript generics from `JsValue`
// inputs. The Rust functions below keep dynamic JS objects at the WASM
// boundary and validate them at runtime, while this custom section replaces the
// generated `any` declarations with the compile-time API TypeScript users need.
#[wasm_bindgen(typescript_custom_section)]
const SCHEMA_TYPES: &'static str = r#"
export type SchemaPrimitiveType = "string" | "number" | "integer" | "boolean" | "object" | "array";
export type CredentialData = Record<string, unknown>;
export type SchemaFieldFor<T> =
  T extends string ? "string" :
  T extends number ? "number" | "integer" :
  T extends boolean ? "boolean" :
  T extends readonly unknown[] ? "array" :
  T extends CredentialData ? SchemaFieldInput<T> | { fields: SchemaFieldInput<T> } | "object" :
  SchemaPrimitiveType;
export type SchemaFieldMap<T extends CredentialData> = {
  readonly [K in Extract<keyof T, string>]: SchemaFieldFor<T[K]>;
};
export type SchemaFieldList<T extends CredentialData> = readonly ({
  readonly [K in Extract<keyof T, string>]: {
    readonly name: K;
    readonly type: SchemaFieldFor<T[K]>;
  }
}[Extract<keyof T, string>])[];
export type SchemaFieldInput<T extends CredentialData> = SchemaFieldMap<T> | SchemaFieldList<T>;
export interface CredentialSchema<TBlinded extends CredentialData, TVisible extends CredentialData> {
  readonly id: string;
  readonly version: string;
  readonly digest: string;
  readonly fields: {
    readonly blinded: unknown;
    readonly visible: unknown;
  };
  readonly __types?: {
    readonly blinded: TBlinded;
    readonly visible: TVisible;
  };
}
export interface DynamicCredential<TBlinded extends CredentialData, TVisible extends CredentialData> {
  readonly schema: string;
  readonly data: {
    readonly blinded: TBlinded;
    readonly visible: TVisible;
  };
}
export function createSchema<TBlinded extends CredentialData, TVisible extends CredentialData>(
  blindedFields: SchemaFieldInput<TBlinded>,
  visibleFields: SchemaFieldInput<TVisible>,
): CredentialSchema<TBlinded, TVisible>;
export function createCredential<TBlinded extends CredentialData, TVisible extends CredentialData>(
  schema: CredentialSchema<TBlinded, TVisible>,
  blindedData: TBlinded,
  visibleData: TVisible,
): DynamicCredential<TBlinded, TVisible>;
export function schemaDigest(schema: CredentialSchema<CredentialData, CredentialData>): string;
"#;

// Keep these arguments as `JsValue`: callers pass ordinary JS objects/arrays,
// and the custom declarations above provide the generic TypeScript surface.
#[wasm_bindgen(js_name = createSchema, skip_typescript)]
pub fn create_schema(blinded_fields: JsValue, visible_fields: JsValue) -> Result<JsValue, JsError> {
    let blinded_fields = serde_wasm_bindgen::from_value(blinded_fields).map_err(js_error)?;
    let visible_fields = serde_wasm_bindgen::from_value(visible_fields).map_err(js_error)?;
    let schema = create_schema_value(blinded_fields, visible_fields).map_err(js_error)?;
    to_js_value(&schema)
}

// The phantom type parameters live only in TypeScript. Rust re-validates the
// schema digest and data shape here so untyped JS callers cannot bypass checks.
#[wasm_bindgen(js_name = createCredential, skip_typescript)]
pub fn create_credential(
    schema: JsValue,
    blinded_data: JsValue,
    visible_data: JsValue,
) -> Result<JsValue, JsError> {
    let schema = serde_wasm_bindgen::from_value(schema).map_err(js_error)?;
    let blinded_data = serde_wasm_bindgen::from_value(blinded_data).map_err(js_error)?;
    let visible_data = serde_wasm_bindgen::from_value(visible_data).map_err(js_error)?;
    let credential =
        create_credential_value(schema, blinded_data, visible_data).map_err(js_error)?;
    to_js_value(&credential)
}

#[wasm_bindgen(js_name = schemaDigest, skip_typescript)]
pub fn schema_digest(schema: JsValue) -> Result<String, JsError> {
    let schema = serde_wasm_bindgen::from_value(schema).map_err(js_error)?;
    schema_digest_value(&schema).map_err(js_error)
}

pub(crate) fn create_schema_value(
    blinded_fields: Value,
    visible_fields: Value,
) -> SchemaResult<Value> {
    let blinded_fields = normalize_schema_fields(blinded_fields)?;
    let visible_fields = normalize_schema_fields(visible_fields)?;
    let schema_without_digest = json!({
        "id": DEFAULT_SCHEMA_ID,
        "version": DEFAULT_SCHEMA_VERSION,
        "fields": {
            "blinded": blinded_fields,
            "visible": visible_fields,
        },
    });
    let digest = digest_value(&schema_without_digest);

    Ok(json!({
        "id": DEFAULT_SCHEMA_ID,
        "version": DEFAULT_SCHEMA_VERSION,
        "digest": digest,
        "fields": schema_without_digest["fields"].clone(),
    }))
}

pub(crate) fn create_credential_value(
    schema: Value,
    blinded_data: Value,
    visible_data: Value,
) -> SchemaResult<Value> {
    let schema = unwrap_schema_definition(&schema)?;
    let digest = schema
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "schema.digest must be a string".to_owned())?;
    let expected_digest = schema_digest_value(schema)?;
    if digest != expected_digest {
        return Err("schema.digest does not match schema fields".to_owned());
    }

    let fields = schema
        .get("fields")
        .ok_or_else(|| "schema.fields is required".to_owned())?;
    let blinded_fields = fields
        .get("blinded")
        .ok_or_else(|| "schema.fields.blinded is required".to_owned())?;
    let visible_fields = fields
        .get("visible")
        .ok_or_else(|| "schema.fields.visible is required".to_owned())?;
    validate_data_against_fields(&blinded_data, blinded_fields, "credential.blinded")?;
    validate_data_against_fields(&visible_data, visible_fields, "credential.visible")?;

    Ok(json!({
        "schema": digest,
        "data": {
            "blinded": blinded_data,
            "visible": visible_data,
        },
    }))
}

pub(crate) fn schema_digest_value(schema: &Value) -> SchemaResult<String> {
    let schema = unwrap_schema_definition(schema)?;
    let mut schema_without_digest = schema
        .as_object()
        .ok_or_else(|| "schema must be an object".to_owned())?
        .clone();
    schema_without_digest.remove("digest");
    Ok(digest_value(&Value::Object(schema_without_digest)))
}

fn normalize_schema_fields(fields: Value) -> SchemaResult<Value> {
    match fields {
        Value::Object(fields) => normalize_schema_field_map(fields),
        Value::Array(fields) => normalize_schema_field_list(fields),
        _ => Err("schema fields must be an object or field list".to_owned()),
    }
}

fn normalize_schema_field_map(fields: Map<String, Value>) -> SchemaResult<Value> {
    if fields.is_empty() {
        return Err("schema fields cannot be empty".to_owned());
    }

    let mut normalized = Map::new();
    for (name, field) in fields {
        validate_field_name(&name)?;
        normalized.insert(name, normalize_schema_field(field)?);
    }
    Ok(Value::Object(normalized))
}

fn normalize_schema_field_list(fields: Vec<Value>) -> SchemaResult<Value> {
    if fields.is_empty() {
        return Err("schema fields cannot be empty".to_owned());
    }

    let mut normalized = Map::new();
    for field in fields {
        match field {
            Value::String(name) => {
                validate_field_name(&name)?;
                normalized.insert(name, Value::String("string".to_owned()));
            }
            Value::Object(mut field) => {
                let name = field
                    .remove("name")
                    .and_then(|name| name.as_str().map(ToOwned::to_owned))
                    .ok_or_else(|| "field list entries must include a string name".to_owned())?;
                validate_field_name(&name)?;

                let field = match field.remove("fields") {
                    Some(fields) => normalize_schema_fields(fields)?,
                    None => normalize_schema_field(
                        field
                            .remove("type")
                            .ok_or_else(|| "field list entries must include type".to_owned())?,
                    )?,
                };
                normalized.insert(name, field);
            }
            _ => return Err("field list entries must be strings or field objects".to_owned()),
        }
    }

    Ok(Value::Object(normalized))
}

fn normalize_schema_field(field: Value) -> SchemaResult<Value> {
    match field {
        Value::String(field_type) => {
            validate_field_type(&field_type)?;
            Ok(Value::String(field_type))
        }
        Value::Object(mut field) => {
            if let Some(fields) = field.remove("fields") {
                return normalize_schema_fields(fields);
            }

            if let Some(field_type) = field.get("type").and_then(Value::as_str) {
                validate_field_type(field_type)?;
                return Ok(Value::String(field_type.to_owned()));
            }

            normalize_schema_field_map(field)
        }
        _ => Err("schema field definitions must be type strings or nested objects".to_owned()),
    }
}

fn validate_data_against_fields(data: &Value, fields: &Value, path: &str) -> SchemaResult<()> {
    let data = data
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let fields = fields
        .as_object()
        .ok_or_else(|| format!("{path} schema must be an object"))?;

    for name in data.keys() {
        if !fields.contains_key(name) {
            return Err(format!("{path}.{name} is not defined by schema"));
        }
    }

    for (name, field) in fields {
        let field_path = format!("{path}.{name}");
        let value = data
            .get(name)
            .ok_or_else(|| format!("{field_path} is required"))?;
        validate_value_against_field(value, field, &field_path)?;
    }

    Ok(())
}

fn validate_value_against_field(value: &Value, field: &Value, path: &str) -> SchemaResult<()> {
    match field {
        Value::String(field_type) => {
            let matches = match field_type.as_str() {
                "string" => value.is_string(),
                "number" => value.is_number(),
                "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
                "boolean" => value.is_boolean(),
                "object" => value.is_object(),
                "array" => value.is_array(),
                _ => false,
            };

            if matches {
                Ok(())
            } else {
                Err(format!("{path} must be {field_type}"))
            }
        }
        Value::Object(_) => validate_data_against_fields(value, field, path),
        _ => Err(format!("{path} has invalid schema field")),
    }
}

fn unwrap_schema_definition(schema: &Value) -> SchemaResult<&Value> {
    if schema.get("fields").is_some() {
        return Ok(schema);
    }

    schema
        .get("schema")
        .ok_or_else(|| "schema must include fields".to_owned())?
        .as_object()
        .map(|_| &schema["schema"])
        .ok_or_else(|| "schema.schema must be an object".to_owned())
}

fn validate_field_name(name: &str) -> SchemaResult<()> {
    if name.is_empty() {
        return Err("schema field names cannot be empty".to_owned());
    }
    Ok(())
}

fn validate_field_type(field_type: &str) -> SchemaResult<()> {
    match field_type {
        "string" | "number" | "integer" | "boolean" | "object" | "array" => Ok(()),
        _ => Err(format!("unsupported schema field type: {field_type}")),
    }
}

fn digest_value(value: &Value) -> String {
    let canonical = canonical_json(value);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", hex_encode(&digest))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("serializing primitive JSON cannot fail")
        }
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{values}]")
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let entries = keys
                .into_iter()
                .map(|key| {
                    let key_json =
                        serde_json::to_string(key).expect("serializing JSON key cannot fail");
                    format!("{key_json}:{}", canonical_json(&object[key]))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{entries}}}")
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn to_js_value(value: &impl Serialize) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_error)
}

fn js_error(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_schema_adds_stable_digest() {
        let first = create_schema_value(
            json!({
                "holder_pubkey": "string",
            }),
            json!({
                "score": "number",
                "issuer": "string",
            }),
        )
        .unwrap();
        let second = create_schema_value(
            json!({
                "holder_pubkey": "string",
            }),
            json!({
                "issuer": "string",
                "score": "number",
            }),
        )
        .unwrap();

        assert_eq!(first["digest"], second["digest"]);
        assert_eq!(first["fields"]["visible"]["score"], "number");
    }

    #[test]
    fn create_schema_accepts_field_list() {
        let schema = create_schema_value(
            json!([
                { "name": "holder_pubkey", "type": "string" },
            ]),
            json!([
                { "name": "issuer_id_pubkey", "type": "string" },
                { "name": "score", "type": "number" },
            ]),
        )
        .unwrap();

        assert_eq!(schema["fields"]["blinded"]["holder_pubkey"], "string");
        assert_eq!(schema["fields"]["visible"]["issuer_id_pubkey"], "string");
        assert_eq!(schema["fields"]["visible"]["score"], "number");
    }

    #[test]
    fn create_credential_validates_dynamic_data_shape() {
        let schema = create_schema_value(
            json!({
                "holder_pubkey": "string",
            }),
            json!({
                "issuer_id_pubkey": "string",
                "score": "number",
                "profile": {
                    "display_name": "string",
                },
            }),
        )
        .unwrap();
        let credential = create_credential_value(
            schema.clone(),
            json!({
                "holder_pubkey": "holder",
            }),
            json!({
                "issuer_id_pubkey": "issuer",
                "score": 7,
                "profile": {
                    "display_name": "Alice",
                },
            }),
        )
        .unwrap();

        assert_eq!(credential["schema"], schema["digest"]);
        assert_eq!(credential["data"]["blinded"]["holder_pubkey"], "holder");
        assert_eq!(credential["data"]["visible"]["score"], 7);
    }

    #[test]
    fn create_credential_rejects_extra_fields() {
        let schema = create_schema_value(
            json!({
                "holder_pubkey": "string",
            }),
            json!({
                "score": "number",
            }),
        )
        .unwrap();
        let credential = create_credential_value(
            schema,
            json!({
                "holder_pubkey": "holder",
            }),
            json!({
                "score": 7,
                "unexpected": true,
            }),
        );

        assert!(credential.is_err());
    }
}
