import terser from '@rollup/plugin-terser';

export default [
    {
        input: 'scripts/id-verifier.js',
        output: [{
            file: 'build/id-verifier.js',
            format: 'es',
        }, {
            file: 'build/id-verifier.min.js',
            format: 'es',
            plugins: [
                terser({ mangle: { keep_classnames: true, keep_fnames: true }}),
            ],
        }],
    }
];
