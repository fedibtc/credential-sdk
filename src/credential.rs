use crate::keys::{finalize_pbrsa_signature, PbrsaKeyPair, PbrsaPublicKey};
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
export type SchemaFieldDefinition =
  | string
  | { readonly name: string; readonly type: SchemaPrimitiveType }
  | { readonly name: string; readonly fields: SchemaFieldList };
export type SchemaFieldList = readonly SchemaFieldDefinition[];
export type PrimitiveDataFor<TType> =
  TType extends "string" ? string :
  TType extends "number" | "integer" ? number :
  TType extends "boolean" ? boolean :
  TType extends "object" ? CredentialData :
  TType extends "array" ? unknown[] :
  unknown;
export type SchemaFieldOutputFor<TField> =
  TField extends string ? { readonly [K in TField]: "string" } :
  TField extends { readonly name: infer TName extends string; readonly fields: infer TFields extends SchemaFieldList } ? { readonly [K in TName]: SchemaFieldsFromList<TFields> } :
  TField extends { readonly name: infer TName extends string; readonly type: infer TType extends SchemaPrimitiveType } ? { readonly [K in TName]: TType } :
  never;
export type SchemaFieldDataFor<TField> =
  TField extends string ? { readonly [K in TField]: string } :
  TField extends { readonly name: infer TName extends string; readonly fields: infer TFields extends SchemaFieldList } ? { readonly [K in TName]: DataFromSchemaFieldList<TFields> } :
  TField extends { readonly name: infer TName extends string; readonly type: infer TType extends SchemaPrimitiveType } ? { readonly [K in TName]: PrimitiveDataFor<TType> } :
  never;
export type UnionToIntersection<T> =
  (T extends unknown ? (value: T) => void : never) extends (value: infer TResult) => void ? TResult : never;
export type Simplify<T> = { readonly [K in keyof T]: T[K] } & {};
export type SchemaFieldsFromList<TFields extends SchemaFieldList> = Simplify<UnionToIntersection<SchemaFieldOutputFor<TFields[number]>>>;
export type DataFromSchemaFieldList<TFields extends SchemaFieldList> = Simplify<UnionToIntersection<SchemaFieldDataFor<TFields[number]>>>;
export type ByteArray = readonly number[];
export type AnyCredentialSchema = CredentialSchema<CredentialData, CredentialData, unknown, unknown>;
export type BlindedDataForSchema<TSchema> =
  TSchema extends CredentialSchema<infer TBlinded, infer _TVisible, unknown, unknown> ? TBlinded : never;
export type VisibleDataForSchema<TSchema> =
  TSchema extends CredentialSchema<infer _TBlinded, infer TVisible, unknown, unknown> ? TVisible : never;
export type CredentialInfoForSchema<TSchema> = Simplify<
  { readonly schema: string } & VisibleDataForSchema<TSchema>
>;
export interface CredentialSchema<
  TBlinded extends CredentialData,
  TVisible extends CredentialData,
  TBlindedFields = unknown,
  TVisibleFields = unknown,
> {
  readonly id: string;
  readonly version: string;
  readonly digest: string;
  readonly fields: {
    readonly blinded: TBlindedFields;
    readonly visible: TVisibleFields;
  };
  readonly __types?: {
    readonly blinded: TBlinded;
    readonly visible: TVisible;
  };
}
export interface BlindedPayload<TSchema extends AnyCredentialSchema> {
  readonly schema: string;
  readonly payload: unknown;
  readonly __schema: TSchema;
}
export interface CredentialTemplate<TSchema extends AnyCredentialSchema> {
  readonly credential: {
    readonly info: CredentialInfoForSchema<TSchema>;
    readonly blind_msg: BlindedDataForSchema<TSchema>;
  };
}
export interface BlindSignedCredential<TSchema extends AnyCredentialSchema> {
  readonly credential: {
    readonly info: CredentialInfoForSchema<TSchema>;
    readonly blind_msg: ByteArray;
  };
  readonly proof: {
    readonly signature: ByteArray;
    readonly blinded_msg: ByteArray;
    readonly blind_msg: ByteArray;
    readonly info: ByteArray;
    readonly messageRandomizer: ByteArray;
    readonly blindingSecret: ByteArray;
  };
}
export interface VerifiableCredential<TSchema extends AnyCredentialSchema> {
  readonly credential: {
    readonly info: CredentialInfoForSchema<TSchema>;
    readonly blind_msg: BlindedDataForSchema<TSchema>;
  };
  readonly proof: {
    readonly signature: ByteArray;
  };
}
export function createSchema<
  const TBlindedFields extends SchemaFieldList,
  const TVisibleFields extends SchemaFieldList,
>(
  blindedFields: TBlindedFields,
  visibleFields: TVisibleFields,
): CredentialSchema<
  DataFromSchemaFieldList<TBlindedFields>,
  DataFromSchemaFieldList<TVisibleFields>,
  SchemaFieldsFromList<TBlindedFields>,
  SchemaFieldsFromList<TVisibleFields>
>;
export function blind<TSchema extends AnyCredentialSchema>(
  schema: TSchema,
  blindedData: BlindedDataForSchema<TSchema>,
): BlindedPayload<TSchema>;
export function createCredential<TSchema extends AnyCredentialSchema>(
  schema: TSchema,
  blindedPayload: BlindedPayload<TSchema>,
  visibleData: VisibleDataForSchema<TSchema>,
): CredentialTemplate<TSchema>;
export function blindSignCredential<TSchema extends AnyCredentialSchema>(
  schema: TSchema,
  blindedPayload: BlindedPayload<TSchema>,
  visibleData: VisibleDataForSchema<TSchema>,
  blindingKeyPair: PbrsaKeyPair,
): BlindSignedCredential<TSchema>;
export function finalizeCredential<TSchema extends AnyCredentialSchema>(
  signedCredential: BlindSignedCredential<TSchema>,
  blindingPublicKey: PbrsaPublicKey,
): VerifiableCredential<TSchema>;
export function schemaDigest(schema: AnyCredentialSchema): string;
"#;

// Keep these arguments as `JsValue`: callers pass ordinary JS objects/arrays,
// and the custom declarations above provide the generic TypeScript surface.
/// Creates a dynamic credential schema from separate blinded and visible field lists.
///
/// The returned schema includes normalized field maps and a stable digest over
/// the schema contents. TypeScript callers should use the generated
/// `createSchema(blindedFields, visibleFields)` declaration for schema-specific
/// type inference.
#[wasm_bindgen(js_name = createSchema, skip_typescript)]
pub fn create_schema(blinded_fields: JsValue, visible_fields: JsValue) -> Result<JsValue, JsError> {
    let blinded_fields = serde_wasm_bindgen::from_value(blinded_fields).map_err(js_error)?;
    let visible_fields = serde_wasm_bindgen::from_value(visible_fields).map_err(js_error)?;
    let schema = create_schema_value(blinded_fields, visible_fields).map_err(js_error)?;
    to_js_value(&schema)
}

/// Validates and packages holder-hidden credential data for a schema.
///
/// The returned blinded payload records the schema digest and the original
/// holder-hidden data. It is not cryptographically blinded yet; that happens
/// during `blindSignCredential` when the payload is converted into PBRSA input.
#[wasm_bindgen(js_name = blind, skip_typescript)]
pub fn blind(schema: JsValue, blinded_data: JsValue) -> Result<JsValue, JsError> {
    let schema = serde_wasm_bindgen::from_value(schema).map_err(js_error)?;
    let blinded_data = serde_wasm_bindgen::from_value(blinded_data).map_err(js_error)?;
    let blinded_payload = blind_value(schema, blinded_data).map_err(js_error)?;
    to_js_value(&blinded_payload)
}

/// Assembles an unsigned credential template from a schema, blinded payload, and visible data.
///
/// The resulting template has the protocol credential shape:
/// `credential.info` contains issuer-visible data plus the schema digest, and
/// `credential.blind_msg` contains the holder-hidden data in unblinded form.
///
/// The phantom type parameters live only in TypeScript. Rust re-validates the
/// schema digest and data shape here so untyped JS callers cannot bypass checks.
#[wasm_bindgen(js_name = createCredential, skip_typescript)]
pub fn create_credential(
    schema: JsValue,
    blinded_payload: JsValue,
    visible_data: JsValue,
) -> Result<JsValue, JsError> {
    let schema = serde_wasm_bindgen::from_value(schema).map_err(js_error)?;
    let blinded_payload = serde_wasm_bindgen::from_value(blinded_payload).map_err(js_error)?;
    let visible_data = serde_wasm_bindgen::from_value(visible_data).map_err(js_error)?;
    let credential =
        create_credential_value(schema, blinded_payload, visible_data).map_err(js_error)?;
    to_js_value(&credential)
}

/// Partially blind-signs a credential using issuer PBRSA keys.
///
/// The visible credential `info` is used as PBRSA public info, while
/// `blind_msg` is the hidden message. The returned blind-signed credential
/// carries a blinded `credential.blind_msg`, a blind signature in
/// `proof.signature`, and the holder-side state required for finalization.
#[wasm_bindgen(js_name = blindSignCredential, skip_typescript)]
pub fn blind_sign_credential(
    schema: JsValue,
    blinded_payload: JsValue,
    visible_data: JsValue,
    blinding_key_pair: &PbrsaKeyPair,
) -> Result<JsValue, JsError> {
    let schema = serde_wasm_bindgen::from_value(schema).map_err(js_error)?;
    let blinded_payload = serde_wasm_bindgen::from_value(blinded_payload).map_err(js_error)?;
    let visible_data = serde_wasm_bindgen::from_value(visible_data).map_err(js_error)?;
    let signed_credential =
        blind_sign_credential_value(schema, blinded_payload, visible_data, blinding_key_pair)?;
    to_js_value(&signed_credential)
}

/// Finalizes a blind-signed credential into a holder-stored verifiable credential.
///
/// This unblinds the signature, verifies the finalized signature against the
/// original `blind_msg` and `info`, and returns a credential whose proof
/// contains the unblinded issuer signature.
#[wasm_bindgen(js_name = finalizeCredential, skip_typescript)]
pub fn finalize_credential(
    signed_credential: JsValue,
    blinding_public_key: &PbrsaPublicKey,
) -> Result<JsValue, JsError> {
    let signed_credential = serde_wasm_bindgen::from_value(signed_credential).map_err(js_error)?;
    let credential = finalize_credential_value(signed_credential, blinding_public_key)?;
    to_js_value(&credential)
}

/// Computes the stable digest for a credential schema.
///
/// The input may be either a schema object or a wrapper containing a `schema`
/// object. The digest is computed after removing the existing `digest` field,
/// so it can be used to validate a schema's embedded digest.
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

pub(crate) fn blind_value(schema: Value, blinded_data: Value) -> SchemaResult<Value> {
    let schema = unwrap_schema_definition(&schema)?;
    let digest = validated_schema_digest(schema)?;
    let blinded_fields = schema
        .get("fields")
        .and_then(|fields| fields.get("blinded"))
        .ok_or_else(|| "schema.fields.blinded is required".to_owned())?;
    validate_data_against_fields(&blinded_data, blinded_fields, "blinded")?;

    Ok(json!({
        "schema": digest,
        "payload": blinded_data,
    }))
}

pub(crate) fn create_credential_value(
    schema: Value,
    blinded_payload: Value,
    visible_data: Value,
) -> SchemaResult<Value> {
    let schema = unwrap_schema_definition(&schema)?;
    let digest = validate_credential_parts(
        schema,
        &blinded_payload,
        &visible_data,
        "credential.blinded.payload",
        "credential.visible",
    )?;
    credential_template_value(&digest, &blinded_payload, &visible_data)
}

fn credential_template_value(
    digest: &str,
    blinded_payload: &Value,
    visible_data: &Value,
) -> SchemaResult<Value> {
    let blinded_data = blinded_payload
        .get("payload")
        .ok_or_else(|| "blinded payload is missing payload data".to_owned())?;
    Ok(json!({
        "credential": {
            "info": credential_info_value(digest, visible_data)?,
            "blind_msg": blinded_data,
        },
    }))
}

fn credential_info_value(digest: &str, visible_data: &Value) -> SchemaResult<Value> {
    let mut info = visible_data
        .as_object()
        .ok_or_else(|| "credential.info visible data must be an object".to_owned())?
        .clone();
    info.insert("schema".to_owned(), Value::String(digest.to_owned()));
    Ok(Value::Object(info))
}

pub(crate) fn blind_sign_credential_value(
    schema: Value,
    blinded_payload: Value,
    visible_data: Value,
    blinding_key_pair: &PbrsaKeyPair,
) -> Result<Value, JsError> {
    let schema = unwrap_schema_definition(&schema).map_err(js_error)?;
    let digest = validate_credential_parts(
        schema,
        &blinded_payload,
        &visible_data,
        "signedCredential.blinded.payload",
        "signedCredential.visible",
    )
    .map_err(js_error)?;
    let info = credential_info_value(&digest, &visible_data).map_err(js_error)?;
    let blind_msg_data = blinded_payload
        .get("payload")
        .ok_or_else(|| JsError::new("blinded payload is missing payload data"))?;
    let blind_msg = canonical_json(blind_msg_data).into_bytes();
    let info_bytes = canonical_json(&info).into_bytes();

    let public_key = blinding_key_pair.public_key();
    let secret_key = blinding_key_pair.secret_key();
    let blinding_result = public_key.blind(blind_msg.clone(), info_bytes.clone())?;
    let blinded_msg = blinding_result.blind_message();
    let blind_signature = secret_key.blind_sign(blinded_msg.clone(), info_bytes.clone())?;

    Ok(json!({
        "credential": {
            "info": info,
            "blind_msg": bytes_value(blinded_msg.clone()),
        },
        "proof": {
            "signature": bytes_value(blind_signature),
            "blinded_msg": bytes_value(blinded_msg),
            "blind_msg": bytes_value(blind_msg),
            "info": bytes_value(info_bytes),
            "messageRandomizer": bytes_value(blinding_result.message_randomizer()),
            "blindingSecret": bytes_value(blinding_result.secret()),
        },
    }))
}

pub(crate) fn finalize_credential_value(
    signed_credential: Value,
    blinding_public_key: &PbrsaPublicKey,
) -> Result<Value, JsError> {
    let signed_credential = signed_credential
        .as_object()
        .ok_or_else(|| JsError::new("signedCredential must be an object"))?;
    let credential = signed_credential
        .get("credential")
        .and_then(Value::as_object)
        .ok_or_else(|| JsError::new("signedCredential.credential must be an object"))?;
    let info = credential
        .get("info")
        .ok_or_else(|| JsError::new("signedCredential.credential.info is required"))?;
    let info_object = info
        .as_object()
        .ok_or_else(|| JsError::new("signedCredential.credential.info must be an object"))?;
    let _digest = info_object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| JsError::new("signedCredential.credential.info.schema must be a string"))?;
    let blind_message_value = credential
        .get("blind_msg")
        .ok_or_else(|| JsError::new("signedCredential.credential.blind_msg is required"))?;
    let proof = signed_credential
        .get("proof")
        .and_then(Value::as_object)
        .ok_or_else(|| JsError::new("signedCredential.proof must be an object"))?;

    let blind_signature = proof_bytes(proof, "signature")?;
    let blind_message =
        value_to_bytes(blind_message_value, "signedCredential.credential.blind_msg")?;
    let proof_blinded_msg = proof_bytes(proof, "blinded_msg")?;
    if blind_message != proof_blinded_msg {
        return Err(JsError::new(
            "signedCredential.credential.blind_msg does not match proof blinded_msg",
        ));
    }
    let blind_msg = proof_bytes(proof, "blind_msg")?;
    let info_bytes = proof_bytes(proof, "info")?;
    let message_randomizer = proof_bytes(proof, "messageRandomizer")?;
    let blinding_secret = proof_bytes(proof, "blindingSecret")?;

    let expected_info = canonical_json(info).into_bytes();
    if info_bytes != expected_info {
        return Err(JsError::new(
            "signedCredential.proof.info does not match credential info",
        ));
    }

    let blinded_data: Value = serde_json::from_slice(&blind_msg).map_err(|error| {
        JsError::new(&format!(
            "signedCredential.proof.blind_msg is not valid JSON: {error}"
        ))
    })?;

    let message_randomizer_for_verify = message_randomizer.clone();
    let blind_msg_for_verify = blind_msg.clone();
    let info_for_verify = info_bytes.clone();
    let signature = finalize_pbrsa_signature(
        blinding_public_key,
        blind_signature,
        blind_message,
        blinding_secret,
        message_randomizer,
        blind_msg,
        info_bytes,
    )?;
    if !blinding_public_key.verify(
        signature.clone(),
        message_randomizer_for_verify,
        blind_msg_for_verify,
        info_for_verify,
    )? {
        return Err(JsError::new(
            "finalized credential signature could not be verified",
        ));
    }

    Ok(json!({
        "credential": {
            "info": info,
            "blind_msg": blinded_data,
        },
        "proof": {
            "signature": bytes_value(signature),
        },
    }))
}

fn validate_credential_parts(
    schema: &Value,
    blinded_payload: &Value,
    visible_data: &Value,
    blinded_path: &str,
    visible_path: &str,
) -> SchemaResult<String> {
    let digest = validated_schema_digest(schema)?;
    let fields = schema
        .get("fields")
        .ok_or_else(|| "schema.fields is required".to_owned())?;
    let blinded_fields = fields
        .get("blinded")
        .ok_or_else(|| "schema.fields.blinded is required".to_owned())?;
    let visible_fields = fields
        .get("visible")
        .ok_or_else(|| "schema.fields.visible is required".to_owned())?;
    let blinded_payload_digest = blinded_payload
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| "blinded payload schema must be a string".to_owned())?;
    if blinded_payload_digest != digest {
        return Err("blinded payload schema does not match credential schema".to_owned());
    }

    let blinded_payload_data = blinded_payload
        .get("payload")
        .ok_or_else(|| "blinded payload is missing payload data".to_owned())?;
    validate_data_against_fields(blinded_payload_data, blinded_fields, blinded_path)?;
    validate_data_against_fields(visible_data, visible_fields, visible_path)?;
    Ok(digest)
}

fn validated_schema_digest(schema: &Value) -> SchemaResult<String> {
    let digest = schema
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "schema.digest must be a string".to_owned())?;
    let expected_digest = schema_digest_value(schema)?;
    if digest != expected_digest {
        return Err("schema.digest does not match schema fields".to_owned());
    }
    Ok(digest.to_owned())
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
        Value::Array(fields) => normalize_schema_field_list(fields),
        _ => Err("schema fields must be a field list".to_owned()),
    }
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
                    None => normalize_field_type(field.remove("type").ok_or_else(|| {
                        "field list entries must include type or fields".to_owned()
                    })?)?,
                };
                normalized.insert(name, field);
            }
            _ => return Err("field list entries must be strings or field objects".to_owned()),
        }
    }

    Ok(Value::Object(normalized))
}

fn normalize_field_type(field_type: Value) -> SchemaResult<Value> {
    match field_type {
        Value::String(field_type) => {
            validate_field_type(&field_type)?;
            Ok(Value::String(field_type))
        }
        _ => Err("schema field types must be strings".to_owned()),
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

fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::Array(bytes.into_iter().map(Value::from).collect())
}

fn proof_bytes(proof: &Map<String, Value>, name: &str) -> Result<Vec<u8>, JsError> {
    value_to_bytes(
        proof
            .get(name)
            .ok_or_else(|| JsError::new(&format!("signedCredential.proof.{name} is required")))?,
        &format!("signedCredential.proof.{name}"),
    )
}

fn value_to_bytes(value: &Value, path: &str) -> Result<Vec<u8>, JsError> {
    let values = value
        .as_array()
        .ok_or_else(|| JsError::new(&format!("{path} must be a byte array")))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let byte = value
                .as_u64()
                .ok_or_else(|| JsError::new(&format!("{path}[{index}] must be an integer byte")))?;
            u8::try_from(byte)
                .map_err(|_| JsError::new(&format!("{path}[{index}] must be between 0 and 255")))
        })
        .collect()
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
            json!([
                { "name": "holder_pubkey", "type": "string" },
            ]),
            json!([
                { "name": "score", "type": "number" },
                { "name": "issuer", "type": "string" },
            ]),
        )
        .unwrap();
        let second = create_schema_value(
            json!([
                { "name": "holder_pubkey", "type": "string" },
            ]),
            json!([
                { "name": "issuer", "type": "string" },
                { "name": "score", "type": "number" },
            ]),
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
            json!([
                { "name": "holder_pubkey", "type": "string" },
            ]),
            json!([
                { "name": "issuer_id_pubkey", "type": "string" },
                { "name": "score", "type": "number" },
                {
                    "name": "profile",
                    "fields": [
                        { "name": "display_name", "type": "string" },
                    ],
                },
            ]),
        )
        .unwrap();
        let blinded_payload = blind_value(
            schema.clone(),
            json!({
                "holder_pubkey": "holder",
            }),
        )
        .unwrap();
        let credential = create_credential_value(
            schema.clone(),
            blinded_payload,
            json!({
                "issuer_id_pubkey": "issuer",
                "score": 7,
                "profile": {
                    "display_name": "Alice",
                },
            }),
        )
        .unwrap();

        assert_eq!(credential["credential"]["info"]["schema"], schema["digest"]);
        assert_eq!(
            credential["credential"]["blind_msg"]["holder_pubkey"],
            "holder"
        );
        assert_eq!(credential["credential"]["info"]["score"], 7);
    }

    #[test]
    fn create_credential_rejects_extra_fields() {
        let schema = create_schema_value(
            json!([
                { "name": "holder_pubkey", "type": "string" },
            ]),
            json!([
                { "name": "score", "type": "number" },
            ]),
        )
        .unwrap();
        let blinded_payload = blind_value(
            schema.clone(),
            json!({
                "holder_pubkey": "holder",
            }),
        )
        .unwrap();
        let credential = create_credential_value(
            schema,
            blinded_payload,
            json!({
                "score": 7,
                "unexpected": true,
            }),
        );

        assert!(credential.is_err());
    }
}
