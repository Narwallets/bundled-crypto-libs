const fs = require('fs')
const browserify = require("browserify");

const outFile = './bundled-libs.js'


function copyFile(){
    const stat=fs.statSync(outFile)
    console.log(outFile,stat.size)

    fs.copyFileSync(outFile,'../narwallets-extension/extension/bundled-libs.js')
}

//--------------------------------
//bundle all libs with browserify
//copy to (assume path of) local narwallets-extension repo
//--------------------------------
function main(){
    try{
    //.exclude('readable-stream')
    browserify("main.js")
    .bundle()
    .pipe(fs.createWriteStream(outFile))
    .on("finish",copyFile)
    }catch(ex){
        console.error(ex);
    }
}

console.clear();
main();
