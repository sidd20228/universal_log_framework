# Extractable reusable patterns

This vanilla dashboard has no exported framework components. Entries describe candidate DraftComponent boundaries in the existing HTML/CSS and DOM factories; they are not existing TSX files. Preserve real dashboard functionality and labels when translating visual direction. Only state/navigation props are proposed; data contracts remain application wiring.

## AppShell
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`
- Category: layout
- Description: Whole page layout with sidebar, header and content.
- Extractable props: none
- Hardcoded: HTML skeleton, class names, brand ULPF

## SidebarNavigation
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: layout
- Description: Anchor navigation for dashboard sections and active tenant.
- Extractable props: activeItem (string, default: overview)
- Hardcoded: Brand, section labels, icon choices, anchor hrefs, CSS

## ConnectionHeader
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: layout
- Description: Tenant/token form, connection state, refresh.
- Extractable props: isConnected (boolean), isLoading (boolean)
- Hardcoded: Labels, input IDs, validators, API token password input, buttons

## PanelCard
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`
- Category: basic
- Description: Shared panel surface and heading wrapper.
- Extractable props: none
- Hardcoded: Surface, radius, heading composition, classes

## ActionButton
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`
- Category: basic
- Description: Primary/quiet/refresh and standard native button variants.
- Extractable props: isDisabled (boolean), isLoading (boolean)
- Hardcoded: Labels, styling and icon shape

## PipelineStage
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: basic
- Description: Clickable stage count and details trigger.
- Extractable props: isActive (boolean), isExpanded (boolean)
- Hardcoded: Five stage names, stage identifiers, CSS, supporting text

## StatusBadge
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: basic
- Description: Semantic status pill/dot for event and connection states.
- Extractable props: isActive (boolean)
- Hardcoded: State color scheme, status vocabulary, classes

## ScopeSelect
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: basic
- Description: Native scope/event filter selection.
- Extractable props: currentSelection (string), isDisabled (boolean)
- Hardcoded: Labels, option generation rule and styles

## DetailDrawer
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: layout
- Description: Right metadata/stage detail pane with close and scrim.
- Extractable props: isOpen (boolean)
- Hardcoded: Titles, close control, focus semantics, CSS

## MetricCard
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: basic
- Description: Headline total plus supporting interpretation.
- Extractable props: none
- Hardcoded: Metric labels, units, semantic totals, CSS

## SourceCoverageItem
- Source: `internal/dashboard/assets/index.html` and `internal/dashboard/assets/styles.css`; state/DOM updates in `internal/dashboard/assets/app.js`
- Category: basic
- Description: Clickable source-family filter and quantity row.
- Extractable props: isActive (boolean), badgeCount (number)
- Hardcoded: Source identity conventions, class names, layout
