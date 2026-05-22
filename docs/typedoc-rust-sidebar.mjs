import { JSX } from "typedoc";

const DOCUMENT_PAGES = {
  quickstart: "Quickstart.html",
  architecture: "Architecture.html",
  "protocol-flow": "Protocol_Flow.html",
  "verification-and-revocation": "Verification_And_Revocation.html",
  "rust-api": "Rust_API.html",
};

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

export function load(app) {
  app.renderer.on("endPage", (page) => {
    if (page.contents) {
      page.contents = fixDocumentSidebarLinks(page.contents);
    }
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
              "GitHub repository",
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
