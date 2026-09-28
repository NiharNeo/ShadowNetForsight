// SVG charts use only observed values; text is assigned through textContent.
const svgNS = 'http://www.w3.org/2000/svg';
function svgElement(tag, attrs = {}, text = '') {
  const node = document.createElementNS(svgNS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text) node.textContent = text;
  return node;
}
let signalSamples = [];
function resetSignalGraph() {
  signalSamples = [];
  drawSignalGraph();
}
function updateSignalGraph(states) {
  for (const state of states || []) {
    signalSamples.push({t: state.window_end, rate: state.packet_count / (state.window_end - state.window_start)});
  }
  signalSamples = signalSamples.slice(-60);
  drawSignalGraph();
}
function drawSignalGraph() {
  const host = document.getElementById('signalGraph');
  if (!host) return;
  const svg = svgElement('svg', {viewBox:'0 0 600 210', role:'img', 'aria-label':'Packet rate over the latest 60 completed capture windows'});
  const max = Math.max(1, ...signalSamples.map(p => p.rate));
  for (let i=0;i<4;i++) {
    const y=24+i*48;
    svg.append(svgElement('line',{x1:48,y1:y,x2:584,y2:y,stroke:'#263d33','stroke-dasharray':'3 5'}));
    svg.append(svgElement('text',{x:40,y:y+4,'text-anchor':'end',fill:'#9eafa6','font-size':10},(max*(3-i)/3).toFixed(max<10?1:0)));
  }
  const pts=signalSamples.map((p,i)=>[48+i*536/Math.max(1,signalSamples.length-1),168-p.rate/max*144]);
  if (pts.length) {
    svg.append(svgElement('path',{d:`M48,168 L${pts.map(p=>p.join(',')).join(' L')} L${pts.at(-1)[0]},168 Z`,fill:'#67e8c7','fill-opacity':'.12'}));
    svg.append(svgElement('polyline',{points:pts.map(p=>p.join(',')).join(' '),fill:'none',stroke:'#67e8c7','stroke-width':2.5}));
    pts.forEach(([px,py],i) => {
      const sample = signalSamples[i];
      const point = svgElement('circle',{cx:px,cy:py,r:4,fill:'#67e8c7','fill-opacity':.3});
      point.append(svgElement('title',{},`${new Date(sample.t*1000).toISOString()} · ${sample.rate.toFixed(2)} packets/sec`));
      svg.append(point);
    });
    const [x,y]=pts.at(-1); svg.append(svgElement('circle',{cx:x,cy:y,r:4,fill:'#bcff3c'}));
  } else svg.append(svgElement('text',{x:316,y:105,'text-anchor':'middle',fill:'#a8bdb2','font-size':12},'Upload a PCAP to plot observed packet activity'));
  svg.append(svgElement('text',{x:48,y:196,fill:'#a8bdb2','font-size':10},'PACKETS / SECOND · 5s WINDOWS'));
  if(signalSamples.length) svg.append(svgElement('text',{x:584,y:196,'text-anchor':'end',fill:'#a8bdb2','font-size':10},`${signalSamples.length} windows · latest ${signalSamples.at(-1).rate.toFixed(1)} pkt/s`));
  host.replaceChildren(svg);
}
function drawConnectionGraph(network) {
  const host = document.getElementById('connectionGraph');
  if (!host) return;
  const edges = network.connections || [];
  const hosts = [...new Set(edges.flatMap(e=>[e.src,e.dst]))];
  const svg = svgElement('svg',{viewBox:'0 0 720 340',role:'img','aria-label':`Observed network: ${hosts.length} displayed hosts and ${edges.length} directed connections`});
  const defs=svgElement('defs'); const marker=svgElement('marker',{id:'netArrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:5,markerHeight:5,orient:'auto-start-reverse'});
  marker.append(svgElement('path',{d:'M0 0 L10 5 L0 10 Z',fill:'#67e8c7'}));defs.append(marker);svg.append(defs);
  const pos=new Map(hosts.map((h,i)=>{const angle=2*Math.PI*i/hosts.length-Math.PI/2;return[h,[360+240*Math.cos(angle),170+118*Math.sin(angle)]];}));
  const max=Math.max(1,...edges.map(e=>e.packets));
  for(const edge of edges){
    const a=pos.get(edge.src),b=pos.get(edge.dst), dx=b[0]-a[0],dy=b[1]-a[1],len=Math.hypot(dx,dy)||1;
    const path=svgElement('path',{d:edge.src===edge.dst?`M${a[0]-12},${a[1]} C${a[0]-65},${a[1]-75} ${a[0]+65},${a[1]-75} ${a[0]+12},${a[1]}`:`M${a[0]+dx/len*24},${a[1]+dy/len*24} Q${(a[0]+b[0])/2-dy*.12},${(a[1]+b[1])/2+dx*.12} ${b[0]-dx/len*26},${b[1]-dy/len*26}`,fill:'none',stroke:'#67e8c7','stroke-opacity':.65,'stroke-width':1+4*edge.packets/max,'marker-end':'url(#netArrow)'});
    path.append(svgElement('title',{},`${edge.src} → ${edge.dst}; protocol ${edge.protocol}; port ${edge.destination_port}; ${edge.packets} packets`));svg.append(path);
  }
  hosts.forEach((name,i)=>{const [x,y]=pos.get(name);const g=svgElement('g');g.append(svgElement('circle',{cx:x,cy:y,r:23,fill:'#10271e',stroke:i===0?'#bcff3c':'#67e8c7','stroke-width':2}));g.append(svgElement('text',{x,y:y+4,'text-anchor':'middle',fill:'#e4f2e8','font-size':11},`H${i+1}`));g.append(svgElement('text',{x,y:y+39,'text-anchor':'middle',fill:'#c8dcd1','font-size':11},name));svg.append(g);});
  if(!hosts.length) svg.append(svgElement('text',{x:360,y:170,'text-anchor':'middle',fill:'#a8bdb2','font-size':13},'Waiting for observed connections'));
  host.replaceChildren(svg);
}
