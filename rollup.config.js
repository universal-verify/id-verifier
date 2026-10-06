import terser from '@rollup/plugin-terser';
import { nodeResolve } from '@rollup/plugin-node-resolve';

const externalDependencies = [
    '@hpke/core',
    'cbor2',
    'pkijs',
    'trusted-issuer-registry',
];

const suppressKnownBundledDependencyWarnings = (warning, defaultHandler) => {
    const warningId = warning.id || '';
    if (
        warningId.includes('/node_modules/@hpke/') &&
        (warning.code === 'INVALID_ANNOTATION' || warning.code === 'THIS_IS_UNDEFINED')
    ) {
        return;
    }
    defaultHandler(warning);
};

export default [
    {
        input: 'scripts/id-verifier.js',
        external: externalDependencies,
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
    }, {
        input: 'scripts/id-verifier.js',
        output: [{
            file: 'build/id-verifier.bundled.js',
            format: 'es',
        }, {
            file: 'build/id-verifier.bundled.min.js',
            format: 'es',
            plugins: [
                terser({ mangle: { keep_classnames: true, keep_fnames: true }}),
            ],
        }],
        plugins: [nodeResolve()],
        onwarn: suppressKnownBundledDependencyWarnings,
    }
];
