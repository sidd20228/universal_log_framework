# Built-in syntax parsers

ULPF parsers interpret bounded event bytes without changing the raw evidence. A parser returns a format-specific document, a status, stable issue codes, and any suffix it could not interpret. Syntax parsing does not claim vendor support and does not infer canonical security meaning; versioned mapping rules perform that later step.

All built-in parsers implement `interpret.SyntaxParser`. Zero-valued limits receive safe defaults. Callers can lower the input, field, depth, and token limits for a listener or source profile. Parser results preserve duplicate values where the source format permits them.

## CEF

The `generic-cef` parser accepts CEF records with or without a Syslog transport prefix. It requires the seven CEF header fields, decodes escaped header pipes and backslashes, and decodes extension `\\=`, `\\\\`, `\\n`, and `\\r` sequences. Unknown or truncated escapes are preserved and reported. Extension values can contain spaces; the next field begins only at a valid `key=` boundary. Duplicate extension keys are retained in arrival order.

The parser follows the OpenText ArcSight [CEF implementation standard](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf). A parsed document contains:

```text
format: cef
fields.header: version, device_vendor, device_product, device_version,
               event_class_id, name, severity
fields.extension: original extension keys and decoded values
fields.raw_extension: the unchanged extension text
fields.transport_prefix: optional text before CEF:
```

## LEEF

The `generic-leef` parser accepts LEEF 1.0 tab-delimited attributes and LEEF 2.0 declared delimiters. A 2.0 delimiter can be one Unicode character or an `x`/`0x` hexadecimal form. The declared and effective delimiter remain in the parsed header. Duplicate attributes are retained in arrival order.

The parser follows IBM QRadar's [LEEF event component specification](https://www.ibm.com/docs/en/qradar-on-cloud?topic=overview-leef-event-components). It also reads the historical `^|` separator form used by the project's synthetic compatibility fixture while recording that exact effective delimiter.

```text
format: leef
fields.header: version, vendor, product, product_version, event_id,
               delimiter, attribute_delimiter
fields.attributes: original attribute keys and values
fields.raw_attributes: the unchanged attribute text
fields.transport_prefix: optional text before LEEF:
```

Malformed required headers and invalid delimiter declarations return `INVALID`. A valid header with a bounded or malformed attribute suffix returns `PARTIALLY_PARSED` and keeps the uninterpreted bytes in `document.unmatched`.

## Declarative RE2 text

The declarative parser accepts strict JSON configuration and compiles patterns with Go's RE2-based `regexp` package. Patterns must be explicitly anchored, contain at least one uniquely named capture, and refer only to declared captures in `required_captures`. Backreferences, look-around, executable hooks, unknown configuration fields, and unbounded input are rejected. Bundle activation should call `ValidateFixtures` with at least one matching and one non-matching case before publishing the parser.

```json
{
  "config_version": "ulpf-re2-parser/1",
  "id": "lab-router-text",
  "version": "1.0.0",
  "format": "router-text",
  "pattern": "^(?P<event>[A-Z_]+)\\|device=(?P<device>[^|]+)$",
  "required_captures": ["event", "device"]
}
```

The output field names are exactly the named captures. The parser performs syntax extraction only; a separate versioned mapping decides whether a capture has canonical security meaning.
