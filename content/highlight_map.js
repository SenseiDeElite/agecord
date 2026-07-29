/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// highlight_map.js
// All valid highlight.js language aliases, used only to decide whether a
// language header should be shown on a fenced code block.  No actual syntax
// highlighting is performed.

'use strict';

export const HLJS_LANGUAGES = new Set([
  '1c','4d','sap-abap','abap','abc','abnf','accesslog','actionscript','as',
  'ada','aiken','ak','ln','alan','i','angelscript','asc','apache','apacheconf',
  'apex','applescript','osascript','arcade','arduino','ino','armasm','arm',
  'asciidoc','adoc','aspectj','autohotkey','autoit','avrasm','awk','mawk',
  'nawk','gawk','ballerina','bal','bash','sh','zsh','basic','bbcode','bicep',
  'blade','bnf','bqn','brainfuck','bf','c','h','csharp','cs','cpp','hpp','cc',
  'hh','c++','h++','cxx','hxx','cal','c3','cos','cls','candid','did',
  'capnproto','capnp','chaos','kaos','chapel','chpl','cisco','clojure','clj',
  'cmake','cobol','standard-cobol','codeowners','coffeescript','coffee','cson',
  'iced','coq','cpc','crmsh','crm','pcmk','crystal','cr','csp','css','curl',
  'cypher','d','dafny','dart','dpr','dfm','pas','pascal','diff','patch',
  'django','jinja','dns','zone','bind','dockerfile','docker','dos','bat','cmd',
  'dsconfig','dts','dust','dst','dylan','ebnf','elixir','elm','erlang','erl',
  'excel','xls','xlsx','extempore','xtlang','xtm','fsharp','fs','fsx','fsi',
  'fsscript','fix','flix','fortran','f90','f95','func','gcode','nc','gams',
  'gms','gauss','gss','godot','gdscript','gherkin','gleam','hbs','glimmer',
  'html.hbs','html.handlebars','htmlbars','gn','gni','go','golang','golo',
  'gololang','gradle','gf','graphql','gql','groovy','gsql','haml','handlebars',
  'haskell','hs','haxe','hx','hlsl','xml','html','xhtml','rss','atom','xjb',
  'xsd','xsl','plist','svg','http','https','hy','hylang','inform7','i7','ini',
  'toml','iptables','irpf90','java','jsp','javascript','js','jsx','jolie',
  'iol','ol','json','jsonc','json5','jsonata','julia','jl','julia-repl',
  'kotlin','kt','l4','legal','lasso','ls','lassoscript','tex','ldif','leaf',
  'lean','less','liquid','lisp','livecodeserver','livescript','lookml','lua',
  'pluto','luau','macaulay2','magik','makefile','mk','mak','make','markdown',
  'md','mkdown','mkd','mathematica','mma','wl','matlab','maxima','mel',
  'mercury','metapost','mint','mips','mipsasm','mirc','mrc','mirth','mizar',
  'mkb','mlir','mojolicious','monkey','moonscript','moon','motoko','mo','n1ql',
  'never','nginx','nginxconf','nim','nimrod','nix','nsis','oak','ocl',
  'objectivec','mm','objc','obj-c','obj-c++','objective-c++','ocaml','ml',
  'odin','glsl','openscad','scad','ruleslanguage','oxygene','papyrus','psc',
  'parser3','perl','pl','pm','pf','phix','php','pine','pinescript','plaintext',
  'txt','text','pony','pgsql','postgres','postgresql','poweron','po',
  'powershell','ps','ps1','prisma','processing','prolog','properties','proto',
  'protobuf','puppet','pp','python','py','gyp','profile','python-repl','pycon',
  'k','kdb','qsharp','qml','r','raku','perl6','p6','pm6','rakumod','pod6',
  'rakudoc','rakuquoting','rakuregexe','cshtml','razor','razor-cshtml',
  'reasonml','re','redbol','rebol','red','red-system','rib','rsl','rescript',
  'res','riscv','riscvasm','risc','riscript','graph','instances','robot','rf',
  'rpm-specfile','rpm','spec','rpm-spec','specfile','ruby','rb','gemspec',
  'podspec','thor','irb','rust','rs','rvt','rvt-script','SAS','sas','scala',
  'scheme','scilab','sci','scss','sfz','shexc','shell','console','smali',
  'smalltalk','st','sml','solidity','sol','spl','sql','stan','stanfuncs',
  'stata','p21','step','stp','iecst','scl','stl','structured-text','stylus',
  'styl','subunit','supercollider','sc','svelte','swift','tcl','tk','terraform',
  'tf','hcl','tap','thrift','toit','tp','tsql','ttcn','ttcnpp','ttcn3','twig',
  'craftcms','typescript','ts','tsx','mts','cts','unicorn-rails-log','unison',
  'u','vala','vbnet','vb','vba','vbscript','vbs','verilog','v','vhdl','vim',
  'voltscript','vss','lotusscript','lss','wgsl','xsharp','xs','prg','axapta',
  'x++','x86asm','x86asmatt','xl','tao','xquery','xpath','xq','xqm','yml',
  'yaml','zenscript','zs','zephir','zep','zig',
]);
