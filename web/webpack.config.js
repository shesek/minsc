const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");
const WorkerPlugin = require('worker-plugin');

const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "production",
  entry: {
    index: "./js/index.js"
  },
  output: {
    path: dist,
    filename: "[name].js",

    // https://github.com/webpack-contrib/worker-loader/issues/174
    globalObject: `typeof self !== 'undefined' ? self : window`,
  },
  externals: {
    //'./pkg' : 'commonjs2 ./pkg',
  },
  /*
  optimization: {
    namedChunks: true,
  },*/
  devServer: {
    contentBase: dist,
  },
  plugins: [
    new CopyPlugin([
      path.resolve(__dirname, "www")
    ]),

    new WasmPackPlugin({
      crateDirectory: path.resolve(__dirname, '..'),
      outDir: path.resolve(__dirname, 'pkg'),
      outName: 'index',
    }),

    new WorkerPlugin,
  ]
};
