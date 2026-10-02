/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// highlight_map.js

// highlight.js aliases used for fenced block language labels only.

// Current revision: https://github.com/highlightjs/highlight.js/blob/7ab86ecad93438c8556590e04b511ee467440c68/SUPPORTED_LANGUAGES.md

'use strict';

export const HLJS_LANGUAGES = new Set([
  '1c','4d','sap-abap','abap','abc','abnf','accesslog','actionscript','as',
  'ada','aiken','ak','ln','alan','i','angelscript','asc','apache','apacheconf',
  'apex','applescript','osascript','arcade','arduino','ino','armasm','arm',
  'asciidoc','adoc','aspectj','astro','astrojs','autohotkey','ahk','autoit','avrasm','awk','mawk',
  'nawk','gawk','ballerina','bal','bash','sh','zsh','basic','bbcode','bicep',
  'blade','bnf','bqn','brainfuck','bf','c','h','csharp','cs','c#','cpp','hpp','cc',
  'hh','c++','h++','cxx','hxx','cal','c3','cos','cls','candid','did',
  'capnproto','capnp','cedar','cedarschema','ceylon','chaos','kaos','chapel','chpl','cisco',
  'clean','icl','dcl','clojure','clj','edn','clojure-repl',
  'cmake','cmake.in','cobol','standard-cobol','codeowners','coffeescript','coffee','cson',
  'iced','coq','cpc','crmsh','crm','pcmk','crystal','cr','csp','css','curl',
  'cypher','d','dafny','dart','dax','delphi','dpr','dfm','pas','pascal','diff','patch',
  'django','jinja','dns','zone','bind','dockerfile','docker','djot','dj',
  'dos','bat','batch','cmd',
  'dsconfig','dts','dust','dst','dylan','ebnf','elixir','ex','exs','elm','erb','erlang','erl','erlang-repl',
  'esql','excel','xls','xlsx','extempore','xtlang','xtm','fsharp','fs','f#','fsx','fsi',
  'fsscript','fix','flix','fortran','f90','f95','freedesktop','desktop','systemd','func','gcode','nc','gml','gams',
  'gms','gauss','gss','godot','gdscript','gherkin','feature','gleam','hbs','glimmer',
  'html.hbs','html.handlebars','htmlbars','gn','gni','go','golang','golo',
  'gololang','gradle','gf','graphql','gql','groovy','gsql','haml','handlebars',
  'haskell','hs','haxe','hx','hlsl','hsp','xml','html','xhtml','rss','atom','xjb',
  'xsd','xsl','plist','wsf','svg','http','https','hy','hylang','inform7','i7','igor','igorpro','ipf','ini',
  'toml','iptables','irpf90','isbl','jaiva','jiv','jva','java','jsp','javascript','js','jsx','mjs','cjs',
  'jboss-cli','wildfly-cli','jolie',
  'iol','ol','json','jsonc','json5','jsonata','julia','jl','julia-repl','jldoctest',
  'kotlin','kt','kts','ktm','ktx','kql','kusto','l4','legal','lasso','ls','lassoscript','latex','tex','ldif','leaf',
  'lean','less','liquid','liq','lisp','livecodeserver','livescript','llvm','lookml','lsl','lua',
  'pluto','luau','m','pq','macaulay2','magik','makefile','mk','mak','make','markdown',
  'md','mkdown','mkd','mathematica','mma','wl','matlab','maxima','mel',
  'mercury','moo','metapost','routeros','mikrotik','mint','mips','mipsasm','mirc','mrc','mirth','mizar',
  'mkb','mlir','mojolicious','monkey','moonbit','mbt','moonscript','moon','motoko','mo','n1ql',
  'nestedtext','nt','never','nginx','nginxconf','nim','nimrod','nix','nixos','node-repl','nsis','oak','ocl',
  'objectivec','mm','objc','obj-c','obj-c++','objective-c++','ocaml','ml',
  'odin','odinlang','glsl','openscad','scad','ruleslanguage','oxygene','papyrus','psc',
  'parser3','perl','pl','pm','pf','pf.conf','phix','php','php-template','pine','pinescript','pkl','plaintext',
  'txt','text','pony','pgsql','postgres','postgresql','poweron','po',
  'powershell','ps','ps1','pwsh','prisma','processing','pde','prolog','properties','proto',
  'protobuf','puppet','pp','purebasic','pb','pbi','python','py','gyp','ipython','profile','python-repl','pycon',
  'q','k','kdb','qsharp','qml','qt','r','raku','perl6','p6','pm6','rakumod','pod6',
  'rakudoc','rakuquoting','rakuregexe','rascript','cshtml','razor','razor-cshtml',
  'reasonml','re','redbol','rebol','red','red-system','rib','rsl','rescript',
  'res','riscv','riscvasm','risc','riscript','roboconf','graph','instances','robot','rf',
  'rpm-specfile','rpm','spec','rpm-spec','specfile','ruby','rb','gemspec',
  'podspec','thor','irb','rust','rs','rvt','rvt-script','SAS','sas','scala',
  'scheme','scm','scilab','sci','scss','sfz','shexc','shell','console','shellsession','smali',
  'smalltalk','st','sml','solidity','sol','spl','sqf','sql','stan','stanfuncs',
  'stata','do','ado','step21','p21','step','stp','iecst','scl','stl','structured-text','stylus',
  'styl','subunit','supercollider','sc','svelte','swift','taggerscript','tcl','tk','terraform',
  'tf','hcl','tap','thrift','toit','tp','tsql','ttcn','ttcnpp','ttcn3','twig',
  'craftcms','typescript','ts','tsx','mts','cts','unicorn-rails-log','unison',
  'u','vala','vbnet','vb','vba','vbscript','vbs','vbscript-html','verilog','v','sv','svh','verse','veryl','vhdl','vim',
  'voltscript','vss','lotusscript','lss','wasm','wgsl','whyml','mlw','wren','xsharp','xs','prg','axapta',
  'x++','x86asm','x86asmatt','xl','tao','xojo','xquery','xpath','xq','xqm','yml',
  'yaml','zenscript','zs','zephir','zep','zig',
]);
