import globals from "globals";
import stylistic from '@stylistic/eslint-plugin'
import { defineConfig } from "eslint/config";

export default defineConfig([
	  {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
            },
        },
        plugins: {
            "@stylistic": stylistic,
        },
  	  	rules: {
  	  		  // Existing rules
  	  		  semi: "error",
  	  		  "prefer-const": "error",
  	  		
  	  		  // Match your existing style
  	  		  "@stylistic/quotes": ["error", "single", { "avoidEscape": true }],
  	  		  "@stylistic/indent": ["error", 4, { "SwitchCase": 1 }],
  	  		  "no-trailing-spaces": "error",
  	  		  "no-unused-vars": ["error", { "varsIgnorePattern": "^_", "caughtErrors": "none" }],
  	  		  "no-undef": "error",
  	  	},
	  },
]);
