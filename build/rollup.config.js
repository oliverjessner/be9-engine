import prettier from 'rollup-plugin-prettier';
import eslint from '@rollup/plugin-eslint';

const prettierConfig = {
    tabWidth: 4,
    singleQuote: true,
    parser: 'babel',
};
const eslintConfig = {
    fix: true,
    throwOnError: true,
    requireConfigFile: false,
    include: ['lib/*.mjs'],
};
const config = {
  input: 'lib/bundle.mjs',
  output: {
    format: 'esm',
    name: 'be9',
    file: './dist/bundle.mjs'
  },
  plugins: [
    eslint(eslintConfig),
    prettier(prettierConfig)
  ]
};

export default config;