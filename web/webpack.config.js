const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");

const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "production",
  entry: {
    index: "./js/index.js"
  },
  output: {
    path: dist,
    filename: "[name].js",
    clean: true,
  },
  experiments: {
    asyncWebAssembly: true,
  },
  devServer: {
    static: dist,
    // Does not work well with WASM changes
    hot: false,
  },
  plugins: [
    new CopyPlugin({ patterns: [
      path.resolve(__dirname, "www")
    ] }),

    new WasmPackPlugin({
      crateDirectory: path.resolve(__dirname, '..'),
      outDir: path.resolve(__dirname, 'pkg'),
      outName: 'index',
      extraArgs: `--no-typescript ${process.env.NO_WASM_OPT ? '--no-opt' : ''} -- --features playground`,
    }),
  ],
  module: {
    rules: [
      { test: /\.(minsc|txt)$/, type: 'asset/source' }
    ]
  },
};
