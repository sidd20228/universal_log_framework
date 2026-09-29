# ULPF dashboard redesign

Direction: operator dashboard inspired by the user-supplied light green Donezo reference. Preserve real backend semantics and working DOM contracts, but replace the navy design completely.

Palette: canvas #f4f7f5; surface #ffffff; ink #172e23; primary #177c50; deep #103f2c; soft green #e9f3ed; muted #66766d; amber #996515; error #bc4c50. Charts: accepted green, processed teal, deliveries muted sage with distinct line dashes; queue pending amber, failed red. Table status partial remains amber; the distribution segment uses mint and is never relabeled fully normalized.

Typography: self-hosted DM Sans, weights 400/500/600/700. Display 30px, panels 16px, body 14px, controls 12–13px, chart labels 11px. Corner radii: panels 20px, inputs 10px, buttons pill. Whitespace 8/12/16/20/24/32.

Shell: light left navigation, compact top search/status/connection toolbar. Headline and one primary simulation action. Four metric surfaces; first forest green. Primary row: large live rate chart beside dark green simulation controls and real 3-minute countdown. Secondary analytical row: source mix, backlog, status. Pipeline spans full width. Event table, incoming preview console, origins, and historical throughput remain reachable below.

Motion: short staged page entrance; new receipt highlights only on arrival; real changed counters and pipeline stage updates; subtle running-session status pulse; short new-point chart reveal; accessible reduced-motion alternative. No fake packets or motion claiming measured end-to-end latency.

The user-selected dashboard-green-concept.png is the layout specification, with intentional corrections: retain real existing table fields (no fabricated host/message metadata), no avatar/notification features, no invented metrics, correct session maximum to 3 minutes, preserve all API/auth/tenant caveats. All fonts and app assets embedded for air-gapped use.
