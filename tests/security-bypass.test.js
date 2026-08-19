import tape from 'tape';
import JseEval from '../dist/jse-eval.module.js';

/**
 * Regression tests for the case-insensitive prototype-pollution / RCE
 * bypass reported by Shikhali Jamalzade (2026-08-19).
 *
 * Root cause: the hardcoded member guard in evaluateMember() matched
 * "__proto__" / "prototype" / "constructor" with a bare-lowercase,
 * ungrouped regex (`/^__proto__|prototype|constructor$/`). That let any
 * differently-cased spelling (e.g. "CONSTRUCTOR") through, after which
 * Utils.getKeyValue()'s case-insensitive prototype-chain walk resolved it
 * to the real Object.prototype.constructor, enabling:
 *
 *   x.CONSTRUCTOR.CONSTRUCTOR("return process")()
 *     .mainModule.require("child_process").execSync("id")
 *
 * The fix anchors + groups the regex and adds the `i` flag, so the guard
 * blocks every case variant unconditionally, independent of the
 * `caseSensitive` option.
 */

const disallowedMsg = /Access to member "[^"]+" disallowed/;

tape('security: blocks case-variant spellings of __proto__/prototype/constructor', (t) => {
  const variants = {
    constructor: ['constructor', 'Constructor', 'CONSTRUCTOR', 'constRUCTOR'],
    prototype: ['prototype', 'Prototype', 'PROTOTYPE'],
    __proto__: ['__proto__', '__Proto__', '__PROTO__'],
  };

  // every option shape a host might realistically pass, including the
  // ones the original report (incorrectly) claimed were already safe and
  // the ones that were the actual, exploitable gap.
  const optionSets = [
    { label: 'options omitted', options: undefined },
    { label: 'options = {}', options: {} },
    { label: 'caseSensitive: true', options: { caseSensitive: true } },
    { label: 'caseSensitive: false', options: { caseSensitive: false } },
  ];

  for (const [, spellings] of Object.entries(variants)) {
    for (const spelling of spellings) {
      for (const { label, options } of optionSets) {
        const ctx = { x: {} };
        t.throws(
          () => JseEval.evaluate(JseEval.jsep(`x.${spelling}`), ctx, options),
          disallowedMsg,
          `x.${spelling} blocked (dot, ${label})`
        );
        t.throws(
          () => JseEval.evaluate(JseEval.jsep(`x['${spelling}']`), ctx, options),
          disallowedMsg,
          `x['${spelling}'] blocked (bracket literal, ${label})`
        );
        t.throws(
          () => JseEval.evaluate(JseEval.jsep(`x[p]`), { x: {}, p: spelling }, options),
          disallowedMsg,
          `x[p] blocked (bracket variable, p="${spelling}", ${label})`
        );
      }
    }
  }

  t.end();
});

tape('security: full RCE chain from the report is blocked under every option shape', (t) => {
  const chain = 'x.CONSTRUCTOR.CONSTRUCTOR("return process")().mainModule.require("child_process").execSync("id").toString()';

  t.throws(() => JseEval.evaluate(JseEval.jsep(chain), { x: {} }), disallowedMsg, 'options omitted');
  t.throws(() => JseEval.evaluate(JseEval.jsep(chain), { x: {} }, {}), disallowedMsg, 'options = {}');
  t.throws(() => JseEval.evaluate(JseEval.jsep(chain), { x: {} }, { caseSensitive: true }), disallowedMsg, 'caseSensitive: true');
  t.throws(() => JseEval.evaluate(JseEval.jsep(chain), { x: {} }, { caseSensitive: false }), disallowedMsg, 'caseSensitive: false');

  t.end();
});

tape('security: guard does not over/under-match unrelated property names (regex grouping regression)', (t) => {
  // Before the fix, the ungrouped regex effectively meant:
  //   (^__proto__) | (prototype) | (constructor$)
  // which blocked any name merely *containing* "prototype" and any name
  // merely *ending in* "constructor" -- while a name that only *starts*
  // with "constructor" (but isn't exactly "constructor") was never meant
  // to be blocked either way. All of these are ordinary, safe property
  // names and must evaluate normally.
  const ctx = {
    x: {
      prototypeName: 42,
      myConstructorField: 7,
      constructorFoo: 99,
    },
  };

  t.doesNotThrow(() => JseEval.evaluate(JseEval.jsep('x.prototypeName'), ctx), 'x.prototypeName not blocked');
  t.equal(JseEval.evaluate(JseEval.jsep('x.prototypeName'), ctx), 42, 'x.prototypeName resolves correctly');

  t.doesNotThrow(() => JseEval.evaluate(JseEval.jsep('x.myConstructorField'), ctx), 'x.myConstructorField not blocked');
  t.equal(JseEval.evaluate(JseEval.jsep('x.myConstructorField'), ctx), 7, 'x.myConstructorField resolves correctly');

  t.doesNotThrow(() => JseEval.evaluate(JseEval.jsep('x.constructorFoo'), ctx), 'x.constructorFoo not blocked');
  t.equal(JseEval.evaluate(JseEval.jsep('x.constructorFoo'), ctx), 99, 'x.constructorFoo resolves correctly');

  t.end();
});

tape('security: defaultOptions.caseSensitive is honored even when a partial options object is passed', (t) => {
  // Previously `options || defaultOptions` meant passing ANY explicit
  // options object -- even one unrelated to caseSensitive, like
  // { blockList: [...] } -- silently discarded the documented
  // caseSensitive: true default. Confirm the merge now preserves it.
  const ctx = { x: { Foo: 1 } };

  // Lowercase "foo" must NOT resolve to the differently-cased "Foo" key
  // when caseSensitive defaults to true -- even though we passed an
  // unrelated options object ({ blockList: [] }) that doesn't mention
  // caseSensitive at all.
  t.equal(
    JseEval.evaluate(JseEval.jsep('x.foo'), ctx, { blockList: [] }),
    undefined,
    'case-sensitive default still applies with an unrelated options object set (no case-insensitive fallback from "foo" to "Foo")'
  );

  t.end();
});
