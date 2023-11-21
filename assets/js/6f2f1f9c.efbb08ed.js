"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[1739],{3905:(e,t,n)=>{n.d(t,{Zo:()=>a,kt:()=>u});var r=n(67294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var s=r.createContext({}),p=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},a=function(e){var t=p(e.components);return r.createElement(s.Provider,{value:t},e.children)},m="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,o=e.originalType,s=e.parentName,a=c(e,["components","mdxType","originalType","parentName"]),m=p(n),d=i,u=m["".concat(s,".").concat(d)]||m[d]||f[d]||o;return n?r.createElement(u,l(l({ref:t},a),{},{components:n})):r.createElement(u,l({ref:t},a))}));function u(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=n.length,l=new Array(o);l[0]=d;var c={};for(var s in t)hasOwnProperty.call(t,s)&&(c[s]=t[s]);c.originalType=e,c[m]="string"==typeof e?e:i,l[1]=c;for(var p=2;p<o;p++)l[p]=n[p];return r.createElement.apply(null,l)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},17898:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>l,default:()=>f,frontMatter:()=>o,metadata:()=>c,toc:()=>p});var r=n(87462),i=(n(67294),n(3905));const o={title:"minder completion fish"},l=void 0,c={unversionedId:"ref/cli/minder_completion_fish",id:"ref/cli/minder_completion_fish",title:"minder completion fish",description:"minder completion fish",source:"@site/docs/ref/cli/minder_completion_fish.md",sourceDirName:"ref/cli",slug:"/ref/cli/minder_completion_fish",permalink:"/ref/cli/minder_completion_fish",draft:!1,tags:[],version:"current",frontMatter:{title:"minder completion fish"},sidebar:"minder",previous:{title:"minder completion bash",permalink:"/ref/cli/minder_completion_bash"},next:{title:"minder completion powershell",permalink:"/ref/cli/minder_completion_powershell"}},s={},p=[{value:"minder completion fish",id:"minder-completion-fish",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],a={toc:p},m="wrapper";function f(e){let{components:t,...n}=e;return(0,i.kt)(m,(0,r.Z)({},a,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"minder-completion-fish"},"minder completion fish"),(0,i.kt)("p",null,"Generate the autocompletion script for fish"),(0,i.kt)("h3",{id:"synopsis"},"Synopsis"),(0,i.kt)("p",null,"Generate the autocompletion script for the fish shell."),(0,i.kt)("p",null,"To load completions in your current shell session:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder completion fish | source\n")),(0,i.kt)("p",null,"To load completions for every new session, execute once:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder completion fish > ~/.config/fish/completions/minder.fish\n")),(0,i.kt)("p",null,"You will need to start a new shell for this setup to take effect."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder completion fish [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -h, --help              help for fish\n      --no-descriptions   disable completion descriptions\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "api.stacklok.com")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "minder-cli")\n      --identity-realm string    Identity server realm (default "stacklok")\n      --identity-url string      Identity server issuer URL (default "https://auth.stacklok.com")\n')),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder_completion"},"minder completion"),"\t - Generate the autocompletion script for the specified shell")))}f.isMDXComponent=!0}}]);