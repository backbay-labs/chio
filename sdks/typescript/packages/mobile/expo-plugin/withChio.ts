import { type ConfigPlugin, withPlugins } from '@expo/config-plugins';

import { withChioAndroid } from './withChioAndroid.js';
import { withChioIos } from './withChioIos.js';

export const withChio: ConfigPlugin = (config) =>
  withPlugins(config, [withChioIos, withChioAndroid]);

export default withChio;
