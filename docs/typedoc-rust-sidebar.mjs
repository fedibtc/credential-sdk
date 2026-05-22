import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { JSX } from "typedoc";

const require = createRequire(import.meta.url);

const DOCUMENT_PAGES = {
  quickstart: "Quickstart.html",
  "issue-a-credential": "Issue_A_Credential.html",
  "persist-pending-issuance": "Persist_Pending_Issuance.html",
  "verify-a-credential": "Verify_A_Credential.html",
  "revoke-a-credential": "Revoke_A_Credential.html",
  "import-and-export-issuer-keys": "Import_And_Export_Issuer_Keys.html",
  "import-and-export-holder-keys": "Import_And_Export_Holder_Keys.html",
  "handle-thrown-javascript-errors": "Handle_Thrown_JavaScript_Errors.html",
  "choose-info-vs-blind-msg": "Choose_Info_Vs_Blind_Msg.html",
  "integrate-transport-outside-the-sdk":
    "Integrate_Transport_Outside_The_SDK.html",
  architecture: "Architecture.html",
  "protocol-flow": "Protocol_Flow.html",
  "verification-and-revocation": "Verification_And_Revocation.html",
  "rust-api": "Rust_API.html",
};

const PROJECT_DISPLAY_NAME = "Fedi Credential SDK";
const NPM_MODULE_PAGE = "modules/pkg_fedi_credential_sdk_wasm.html";
const NPM_MODULE_REFLECTION_NAME = "pkg/fedi_credential_sdk_wasm";
const NPM_MODULE_DISPLAY_NAME = "Fedi Credential SDK (npm)";

const PROJECT_OVERVIEW = `
<div class="docblock fedi-project-overview">
  <p>
    This is the Fedi credential SDK. The repository contains two Rust crates
    plus a generated npm package for browser and TypeScript applications.
  </p>
  <ul>
    <li>
      <a href="rust/fedi_credential_sdk_protocol/index.html"><code>fedi-credential-sdk-protocol</code></a>
      is a Rust crate that implements the core issuance, verification,
      canonicalization, and revocation protocol.
    </li>
    <li>
      <a href="rust/fedi_credential_sdk_wasm/index.html"><code>fedi-credential-sdk-wasm</code></a>
      is a Rust crate that exposes the protocol through wasm-bindgen.
    </li>
    <li>
      <a href="${NPM_MODULE_PAGE}"><code>${NPM_MODULE_DISPLAY_NAME}</code></a>
      is the generated npm package consumed by JavaScript and TypeScript apps.
    </li>
  </ul>
</div>`;

function fixDocumentSidebarLinks(html) {
  return html.replace(
    /href="(\.\.\/)?modules\.html#document\.([a-z-]+)"/g,
    (match, parentPrefix = "", documentSlug) => {
      const page = DOCUMENT_PAGES[documentSlug];

      if (!page) {
        return match;
      }

      return `href="${parentPrefix}documents/${page}"`;
    },
  );
}

function regexEscape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function addProjectOverview(html) {
  if (html.includes("fedi-project-overview")) {
    return html;
  }

  return html.replace(
    '</rustdoc-toolbar></div><h2 id="section.modules"',
    `</rustdoc-toolbar></div>${PROJECT_OVERVIEW}<h2 id="section.modules"`,
  );
}

function relativeNpmModulePage(pageUrl) {
  return pageUrl.includes("/") ? `../${NPM_MODULE_PAGE}` : NPM_MODULE_PAGE;
}

function linkProjectTitleToNpmModule(html, pageUrl) {
  const href = relativeNpmModulePage(pageUrl);
  const projectName = regexEscape(PROJECT_DISPLAY_NAME);

  return html
    .replace(
      new RegExp(
        `(<div class="sidebar-crate"><h2><a href=")[^"]+(">${projectName}</a>)`,
        "g",
      ),
      `$1${href}$2`,
    )
    .replace(
      new RegExp(
        `(<h2 class="location"><a href=")[^"]*(">${projectName}</a>)`,
        "g",
      ),
      `$1${href}$2`,
    );
}

function formatNpmModuleName(html) {
  return html
    .replaceAll(
      `>${NPM_MODULE_REFLECTION_NAME}<`,
      `>${NPM_MODULE_DISPLAY_NAME}<`,
    )
    .replaceAll(
      `title="${NPM_MODULE_REFLECTION_NAME}"`,
      `title="${NPM_MODULE_DISPLAY_NAME}"`,
    )
    .replaceAll(
      `<title>${NPM_MODULE_REFLECTION_NAME} -`,
      `<title>${NPM_MODULE_DISPLAY_NAME} -`,
    );
}

function hideNpmModuleDetails(html) {
  return html
    .replace(
      /<h3><a href="#section\.type-aliases">Type Aliases<\/a><\/h3><ul class="block">[\s\S]*?<\/ul>/g,
      "",
    )
    .replace(
      /<h3><a href="#section\.interfaces">Interfaces<\/a><\/h3><ul class="block">[\s\S]*?<\/ul>/g,
      "",
    )
    .replace(
      /<h2 id="section\.type-aliases" class="section-header">Type Aliases[\s\S]*?<\/dl>/g,
      "",
    )
    .replace(
      /<h2 id="section\.interfaces" class="section-header">Interfaces[\s\S]*?<\/dl>/g,
      "",
    );
}

export function load(app) {
  app.renderer.on("beginRender", (event) => {
    const assetsDir = join(event.outputDirectory, "assets");
    mkdirSync(assetsDir, { recursive: true });
    copyFileSync(
      require.resolve("mermaid/dist/mermaid.min.js"),
      join(assetsDir, "mermaid.min.js"),
    );
  });

  app.renderer.on("endPage", (page) => {
    if (page.contents) {
      page.contents = fixDocumentSidebarLinks(page.contents);
      page.contents = linkProjectTitleToNpmModule(page.contents, page.url);
      page.contents = formatNpmModuleName(page.contents);

      if (page.url === "modules.html") {
        page.contents = addProjectOverview(page.contents);
      }

      if (page.url === NPM_MODULE_PAGE) {
        page.contents = hideNpmModuleDetails(page.contents);
      }
    }
  });

  app.renderer.hooks.on("body.end", (context) => {
    if (!context.options.getValue("customJs")) {
      return JSX.createElement(JSX.Fragment, null);
    }

    return JSX.createElement("script", {
      defer: true,
      src: context.relativeURL("assets/custom.js"),
    });
  });

  app.renderer.hooks.on("sidebar.end", (context) => {
    if (!context.model.isProject()) {
      return JSX.createElement(JSX.Fragment, null);
    }

    return JSX.createElement(
      "div",
      { class: "sidebar-elems" },
      JSX.createElement(
        "section",
        null,
        JSX.createElement("h3", null, "Links"),
        JSX.createElement(
          "ul",
          { class: "block" },
          JSX.createElement(
            "li",
            null,
            JSX.createElement(
              "a",
              { href: "https://github.com/fedibtc/credential-sdk" },
              "fedibtc/credential-sdk",
            ),
          ),
          JSX.createElement(
            "li",
            null,
            JSX.createElement(
              "a",
              {
                href: "https://www.npmjs.com/package/@fedibtc/fedi-credential-sdk-wasm",
              },
              "npm package",
            ),
          ),
        ),
      ),
      JSX.createElement(
        "section",
        null,
        JSX.createElement("h3", null, "Rust API"),
        JSX.createElement(
          "ul",
          { class: "block" },
          JSX.createElement(
            "li",
            null,
            JSX.createElement(
              "a",
              {
                href: context.relativeURL(
                  "rust/fedi_credential_sdk_protocol/index.html",
                ),
              },
              "Protocol crate",
            ),
          ),
          JSX.createElement(
            "li",
            null,
            JSX.createElement(
              "a",
              {
                href: context.relativeURL(
                  "rust/fedi_credential_sdk_wasm/index.html",
                ),
              },
              "WASM crate",
            ),
          ),
        ),
      ),
    );
  });
}
