var webpack = require('webpack');
var webpackMerge = require('webpack-merge');
var commonConfig = require('./webpack.common.js');

module.exports = webpackMerge(commonConfig, {
    devtool: 'none',

    plugins: [
        new webpack.NoErrorsPlugin(),
        new webpack.optimize.DedupePlugin(),
        new webpack.optimize.UglifyJsPlugin({
          beautify: false,
          comments: false,
          compress: {
              warnings: false,
              drop_console: true
          },
          mangle: {
              except: ['angular', '$', 'exports', 'require']
          }
        }),
        new webpack.DefinePlugin({
            PRODUCTION: JSON.stringify(true)
        })
    ]
});
