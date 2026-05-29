import {
  type ConfigPlugin,
  withAndroidManifest,
  withProjectBuildGradle,
} from '@expo/config-plugins';

export const withChioAndroid: ConfigPlugin = (config) => {
  const withManifest = withAndroidManifest(config, (mod) => {
    const application = mod.modResults.manifest.application?.[0];
    if (application) {
      application.$ = {
        ...application.$,
        'tools:targetApi': application.$?.['tools:targetApi'] ?? '34',
      };
    }
    return mod;
  });

  return withProjectBuildGradle(withManifest, (mod) => {
    if (!mod.modResults.contents.includes('chio-kernel-mobile-release.aar')) {
      mod.modResults.contents +=
        '\n// Chio mobile AAR is copied in by the prebuild step.\n';
    }
    return mod;
  });
};
