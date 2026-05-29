import { type ConfigPlugin, withPlugins } from '@expo/config-plugins';

import type { ChioPluginProps } from './props.js';
import { withChioAndroid } from './withChioAndroid.js';
import { withChioIos } from './withChioIos.js';

export type { ChioPluginProps } from './props.js';

export const withChio: ConfigPlugin<ChioPluginProps | undefined> = (
  config,
  props,
) => withPlugins(config, [[withChioIos, props], withChioAndroid]);

export default withChio;
