import {
  type ConfigPlugin,
  withDangerousMod,
  withInfoPlist,
} from '@expo/config-plugins';

import type { ChioPluginProps } from './props.js';

// On-device verification is the default: the bundled ChioKernel.xcframework
// validates receipts locally and does not call out to a remote service.
const DEFAULT_RECEIPT_ORACLE = 'local';

export const withChioIos: ConfigPlugin<ChioPluginProps | undefined> = (
  config,
  props,
) => {
  const receiptOracle = props?.receiptOracle ?? DEFAULT_RECEIPT_ORACLE;
  const withInfo = withInfoPlist(config, (mod) => {
    mod.modResults.ChioKernelMobile = {
      framework: 'ChioKernel.xcframework',
      receiptOracle,
    };
    return mod;
  });

  return withDangerousMod(withInfo, [
    'ios',
    async (mod) => {
      mod.modResults.chio = {
        xcframework: 'sdks/swift/Frameworks/ChioKernel.xcframework',
      };
      return mod;
    },
  ]);
};
