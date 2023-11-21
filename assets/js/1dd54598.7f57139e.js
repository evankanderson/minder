"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[1689],{3905:(e,t,r)=>{r.d(t,{Zo:()=>a,kt:()=>f});var n=r(67294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function l(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function p(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var c=n.createContext({}),s=function(e){var t=n.useContext(c),r=t;return e&&(r="function"==typeof e?e(t):l(l({},t),e)),r},a=function(e){var t=s(e.components);return n.createElement(c.Provider,{value:t},e.children)},m="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},u=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,i=e.originalType,c=e.parentName,a=p(e,["components","mdxType","originalType","parentName"]),m=s(r),u=o,f=m["".concat(c,".").concat(u)]||m[u]||d[u]||i;return r?n.createElement(f,l(l({ref:t},a),{},{components:r})):n.createElement(f,l({ref:t},a))}));function f(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=r.length,l=new Array(i);l[0]=u;var p={};for(var c in t)hasOwnProperty.call(t,c)&&(p[c]=t[c]);p.originalType=e,p[m]="string"==typeof e?e:o,l[1]=p;for(var s=2;s<i;s++)l[s]=r[s];return n.createElement.apply(null,l)}return n.createElement.apply(null,r)}u.displayName="MDXCreateElement"},80309:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>c,contentTitle:()=>l,default:()=>d,frontMatter:()=>i,metadata:()=>p,toc:()=>s});var n=r(87462),o=(r(67294),r(3905));const i={title:"minder completion powershell"},l=void 0,p={unversionedId:"ref/cli/minder_completion_powershell",id:"ref/cli/minder_completion_powershell",title:"minder completion powershell",description:"minder completion powershell",source:"@site/docs/ref/cli/minder_completion_powershell.md",sourceDirName:"ref/cli",slug:"/ref/cli/minder_completion_powershell",permalink:"/ref/cli/minder_completion_powershell",draft:!1,tags:[],version:"current",frontMatter:{title:"minder completion powershell"},sidebar:"minder",previous:{title:"minder completion fish",permalink:"/ref/cli/minder_completion_fish"},next:{title:"minder completion zsh",permalink:"/ref/cli/minder_completion_zsh"}},c={},s=[{value:"minder completion powershell",id:"minder-completion-powershell",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],a={toc:s},m="wrapper";function d(e){let{components:t,...r}=e;return(0,o.kt)(m,(0,n.Z)({},a,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"minder-completion-powershell"},"minder completion powershell"),(0,o.kt)("p",null,"Generate the autocompletion script for powershell"),(0,o.kt)("h3",{id:"synopsis"},"Synopsis"),(0,o.kt)("p",null,"Generate the autocompletion script for powershell."),(0,o.kt)("p",null,"To load completions in your current shell session:"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"minder completion powershell | Out-String | Invoke-Expression\n")),(0,o.kt)("p",null,"To load completions for every new session, add the output of the above command\nto your powershell profile."),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"minder completion powershell [flags]\n")),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"  -h, --help              help for powershell\n      --no-descriptions   disable completion descriptions\n")),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "api.stacklok.com")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "minder-cli")\n      --identity-realm string    Identity server realm (default "stacklok")\n      --identity-url string      Identity server issuer URL (default "https://auth.stacklok.com")\n')),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/ref/cli/minder_completion"},"minder completion"),"\t - Generate the autocompletion script for the specified shell")))}d.isMDXComponent=!0}}]);