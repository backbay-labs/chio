/** Configuration options for the Chio Expo config plugin. */
export interface ChioPluginProps {
  /**
   * Identifier for the receipt verification oracle the native kernel uses.
   * Defaults to `"local"`, which performs on-device verification with the
   * bundled ChioKernel framework. Set this to a custom value only when
   * integrating a remote verification service.
   */
  receiptOracle?: string;
}
