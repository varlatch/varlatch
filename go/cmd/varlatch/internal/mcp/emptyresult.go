// SPDX-License-Identifier: Apache-2.0

package mcp

// emptyResultIssues is what zod reports for a tool result whose text is
// undefined: no content block of CallToolResultSchema's union accepts
// {type: "text", text: undefined}. Copied from the TypeScript server's
// answer (testdata/vectors/mcp.json, the "undefined-answers" cases).
const emptyResultIssues = `[
  {
    "code": "invalid_union",
    "errors": [
      [
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "text"
          ],
          "message": "Invalid input: expected string, received undefined"
        }
      ],
      [
        {
          "code": "invalid_value",
          "values": [
            "image"
          ],
          "path": [
            "type"
          ],
          "message": "Invalid input: expected \"image\""
        },
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "data"
          ],
          "message": "Invalid input: expected string, received undefined"
        },
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "mimeType"
          ],
          "message": "Invalid input: expected string, received undefined"
        }
      ],
      [
        {
          "code": "invalid_value",
          "values": [
            "audio"
          ],
          "path": [
            "type"
          ],
          "message": "Invalid input: expected \"audio\""
        },
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "data"
          ],
          "message": "Invalid input: expected string, received undefined"
        },
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "mimeType"
          ],
          "message": "Invalid input: expected string, received undefined"
        }
      ],
      [
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "name"
          ],
          "message": "Invalid input: expected string, received undefined"
        },
        {
          "expected": "string",
          "code": "invalid_type",
          "path": [
            "uri"
          ],
          "message": "Invalid input: expected string, received undefined"
        },
        {
          "code": "invalid_value",
          "values": [
            "resource_link"
          ],
          "path": [
            "type"
          ],
          "message": "Invalid input: expected \"resource_link\""
        }
      ],
      [
        {
          "code": "invalid_value",
          "values": [
            "resource"
          ],
          "path": [
            "type"
          ],
          "message": "Invalid input: expected \"resource\""
        },
        {
          "code": "invalid_union",
          "errors": [
            [
              {
                "expected": "object",
                "code": "invalid_type",
                "path": [],
                "message": "Invalid input: expected object, received undefined"
              }
            ],
            [
              {
                "expected": "object",
                "code": "invalid_type",
                "path": [],
                "message": "Invalid input: expected object, received undefined"
              }
            ]
          ],
          "path": [
            "resource"
          ],
          "message": "Invalid input"
        }
      ]
    ],
    "path": [
      "content",
      0
    ],
    "message": "Invalid input"
  }
]`
