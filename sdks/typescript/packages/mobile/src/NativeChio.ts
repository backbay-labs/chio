export type ChioNativeModule = {
  evaluate(requestJson: string): Promise<string>;
  signReceipt(bodyJson: string, signingSeedHex: string): Promise<string>;
  verifyCapability(tokenJson: string, authorityPubHex: string): Promise<unknown>;
  verifyPassport(
    envelopeJson: string,
    issuerPubHex: string,
    nowSecs: number,
  ): Promise<unknown>;
  attestAppAttest(keyId: string, challengeHex: string): Promise<string>;
  attestPlayIntegrity(nonceHex: string): Promise<string>;
  verifyMobileReceipt(receiptJson: string, evidenceJson: string): Promise<string>;
};

let nativeModule: ChioNativeModule | undefined;

export async function nativeChio(): Promise<ChioNativeModule> {
  if (!nativeModule) {
    const { requireNativeModule } = await import('expo-modules-core');
    nativeModule = requireNativeModule<ChioNativeModule>('Chio');
  }
  return nativeModule;
}
