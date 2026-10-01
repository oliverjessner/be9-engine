import prettier from 'rollup-plugin-prettier';
import { terser } from 'rollup-plugin-terser'; // minifier

const prettierConfig = {
    tabWidth: 4,
    singleQuote: true,
    parser: 'babel',
};
const config = {
  input: 'lib/iife.mjs',
  output: {
    format: 'iife',
    name: 'be8',
    file: './dist/bundle.min.js',
    preferConst: true,
  },
  plugins: [
    prettier(prettierConfig),
    terser()
  ]
};

export default config;
