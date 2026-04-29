# Changelog

## Unreleased

### Deprecation Notice

- The older direct-use APIs in `ChioOpenAiAdapter`, including direct tool-call
  extraction, execution, and result-conversion helpers, are superseded for
  provider-native mediation by the `ProviderAdapter` surface behind the
  `provider-adapter` feature. They remain compiled on the default feature set
  for one minor release after M07 closes so downstream users can migrate
  deliberately.
