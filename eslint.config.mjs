import tseslint from 'typescript-eslint';

// One config for the whole workspace. Each package's `lint` script runs `eslint .`
// from its own directory and finds this file by walking up, so a rule change lands
// on every package at once instead of drifting across six copies.
const hygieneRules = {
  // `_name` is how this codebase says "bound but deliberately unread", mostly in tests
  // that drain a stream for its side effects. Without the pattern the convention reads
  // as a defect.
  '@typescript-eslint/no-unused-vars': [
    'error',
    {
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
      caughtErrorsIgnorePattern: '^_',
      destructuredArrayIgnorePattern: '^_',
    },
  ],
  // An async signature here is part of an interface contract, not a promise to await
  // something: a mock backend and a real one have to stay interchangeable. Requiring an
  // await would only be satisfiable by a statement that does nothing.
  '@typescript-eslint/require-await': 'off',
};

export default tseslint.config(
  { ignores: ['**/dist/**'] },
  {
    // Shipped code gets the rules that need the type checker. `projectService` resolves a
    // file to the `tsconfig.json` beside its package, and that is the one config each
    // package builds from, whose include is only `src`. The `tsconfig.test.json` and
    // `tsconfig.scripts.json` files that do cover `test/` and `scripts/` are typecheck and
    // generation configs, not the one the parser is pointed at, so asking for a project over
    // a test fails to parse before any rule runs. That is why they sit in the next block.
    files: ['**/src/**/*.ts'],
    extends: [tseslint.configs.strictTypeChecked],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      ...hygieneRules,
      // The strict set disallows every numeric interpolation, which reads as noise in a
      // codebase whose error messages carry lengths and indices: `${seed.length}` has
      // exactly one meaning. Values that stringify ambiguously stay flagged.
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
    },
  },
  {
    // Tests, generator scripts and this file: hygiene rules that need no type info.
    files: ['**/*.ts', '**/*.mjs'],
    extends: [tseslint.configs.recommended],
    rules: hygieneRules,
  },
);
