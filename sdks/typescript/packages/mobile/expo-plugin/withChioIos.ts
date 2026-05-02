import {
  type ConfigPlugin,
  withDangerousMod,
  withInfoPlist,
} from '@expo/config-plugins';

export const withChioIos: ConfigPlugin = (config) => {
  const withInfo = withInfoPlist(config, (mod) => {
    mod.modResults.ChioKernelMobile = {
      framework: 'ChioKernel.xcframework',
      receiptOracle: 'M01',
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
