const fs=require('fs'),path=require('path');
const {encode}=require('gpt-tokenizer/encoding/o200k_base');
const dir=process.argv[2];  // path to github-mcp-server/pkg/github/__toolsnaps__
const byName={};
for(const f of fs.readdirSync(dir).filter(f=>f.endsWith('.snap'))){
  const d=JSON.parse(fs.readFileSync(path.join(dir,f),'utf8'));
  const wire={name:d.name,description:d.description,inputSchema:d.inputSchema};
  const t=encode(JSON.stringify(wire)).length;
  const ro=!!(d.annotations&&d.annotations.readOnlyHint);
  // keep the largest variant per tool name (some tools have feature-flag variants)
  if(!byName[d.name]||byName[d.name].tokens<t) byName[d.name]={name:d.name,tokens:t,readOnly:ro,file:f};
}
const tools=Object.values(byName).sort((a,b)=>b.tokens-a.tokens);
fs.writeFileSync('github_tool_tokens.json',JSON.stringify(tools,null,1));
const sum=a=>a.reduce((s,x)=>s+x.tokens,0);
console.log('snap files',fs.readdirSync(dir).length,'unique tool names',tools.length);
console.log('total tokens',sum(tools),'mean',Math.round(sum(tools)/tools.length),'median',tools[Math.floor(tools.length/2)].tokens);
console.log('read-only',tools.filter(t=>t.readOnly).length,sum(tools.filter(t=>t.readOnly)),'write',tools.filter(t=>!t.readOnly).length,sum(tools.filter(t=>!t.readOnly)));
console.log('top5',tools.slice(0,5).map(t=>t.name+':'+t.tokens).join(', '));
const bundle=['create_pull_request','list_issues','search_code','get_file_contents','pull_request_read','issue_read'];
for(const b of bundle) console.log(b, byName[b]?byName[b].tokens:'MISSING');
