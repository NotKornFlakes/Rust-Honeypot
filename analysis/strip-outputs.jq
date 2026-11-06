# Git's clean filter for notebooks (see .gitattributes). Outputs hold log data, so git only ever
# stores the code: no outputs, no execution counts, no run timestamps, no widget state.
.cells |= map(
  if .cell_type == "code" then .outputs = [] | .execution_count = null else . end
  | del(.metadata.execution)
)
| .metadata |= del(.widgets)
