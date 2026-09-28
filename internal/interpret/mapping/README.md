# Declarative mappings

The mapping engine only writes reviewed target paths from the built-in target
allowlist. A rule names one exact parsed source path and one target. Failed
conversions and unknown taxonomy values stay in `Result.Unmapped` and produce a
structured issue.

```json
{
  "config_version": "ulpf-mapping/1",
  "id": "lab-firewall",
  "version": "1.0.0",
  "rules": [
    {
      "id": "source-ip",
      "from": "fields.src",
      "to": "event.src_endpoint.ip",
      "convert": "ip",
      "required": true
    },
    {
      "id": "action",
      "from": "fields.action",
      "to": "event.action",
      "convert": "lowercase",
      "lookup": "action-v1"
    }
  ],
  "taxonomies": {
    "action-v1": {
      "allow": ["accept", "permit"],
      "deny": ["block", "blocked", "drop"]
    }
  }
}
```

Timestamp rules must list their accepted Go layouts. `RFC3339` and
`RFC3339Nano` are accepted aliases. Layouts without a zone use UTC unless the
rule supplies a fixed offset such as `+05:30`; machine-local timezones are not
used.

Slice selectors are also explicit. For example,
`fields.structured_data.net.parameters.src.value` selects the unique element
whose `id`, `name`, or `key` is `net`, followed by the unique `src` parameter.
Zero or multiple matches do not produce a trusted target.
