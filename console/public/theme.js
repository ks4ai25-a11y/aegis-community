// SPDX-License-Identifier: BUSL-1.1
// Applied before the app loads so a light-theme user does not see a dark flash.
try{var t=localStorage.getItem('aegis-theme');if(t!=='dark'&&t!=='light')t=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';document.documentElement.dataset.theme=t;}catch(e){}
