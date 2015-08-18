function days_in_month(a,b){return new Date(b,a,0).getDate()}function date_by_subtracting_days(a,b){return new Date(a.getFullYear(),a.getMonth(),a.getDate()-b,a.getHours(),a.getMinutes(),a.getSeconds(),a.getMilliseconds())}function date_by_subtracting_hours(a,b){return new Date(a.getFullYear(),a.getMonth(),a.getDate(),a.getHours()-b,a.getMinutes(),a.getSeconds(),a.getMilliseconds())}function get_utc_time_hours(){var a=new Date;return new Date(a.getUTCFullYear(),a.getUTCMonth(),a.getUTCDate(),a.getUTCHours(),0,0)}function refresh(){window.location.reload(!0)}function create_chart(a,b,c,d){require(["d3"],function(){function e(){var a=d3.select(this).attr("class");a=a.split(" "),d3.selectAll("."+a[0]).filter("."+a[1]).style("cursor","zoom-in").transition().duration(750).attr("height",r).attr("width",n),d3.select(this).style("cursor","default").transition().duration(750).attr("height",r*o).attr("width",n*o)}for(var f=a,g=[],h=get_utc_time_hours(),i=0;24>i;i++)g.push(date_by_subtracting_hours(h,i));for(var j=[],h=get_utc_time_hours(),i=0;30>i;i++)j.push(date_by_subtracting_days(h,i));var k={top:60,right:30,bottom:50,left:60},l=300,m=0;"hours"==c?m=l/24:"days"==c&&(m=l/30);var n=l+k.left+k.right,o=1.75,p=150;if(0!=d3.max(f))var q=p/d3.max(f);else var q=1;var r=p+k.top+k.bottom;$(".charts").css("height",r*o);var s=d3.select("#"+b).attr("width",n).attr("height",r).attr("preserveAspectRatio","xMidYMin").attr("viewBox","0 0 "+n+" "+r).on("click",e),t=s.selectAll("g").data(f).enter().append("g").attr("transform",function(a,b){return curr_margin=+k.left,curr_margin+=+(b*m),"translate("+curr_margin+","+k.top+")"}).on("mouseenter",function(a){for(var b=1,c=a;c>=10;)c/=10,b++;var d=4*b+10;d3.select(d3.event.path[1]).select(".tool_tip").select("text").attr("transform","translate( "+(k.left-5)+", "+(p-a*q+ +k.top+10)+" )").attr("visibility","visible").text(a),d3.select(d3.event.path[1]).select(".tool_tip").attr("width",d+"px").attr("height","15px").select("rect").attr("transform","translate( "+(+k.left-d)+", "+(p-a*q+ +k.top)+" )").attr("width",d+"px").attr("height","15px").attr("fill","#ebd9b2")}).on("mouseleave",function(a){d3.select(d3.event.path[1]).select(".tool_tip").select("text").attr("visibility","hidden"),d3.select(d3.event.path[1]).select(".tool_tip").select("rect").attr("width","0").attr("height","0").attr("fill","").text(a)});s.append("g").append("text").attr("class","title").attr("text-anchor","end").attr("transform",function(){return"translate( "+l+",15 )"}).text(d),s.append("g").attr("class","axis").append("path").attr("class","x").attr("d",function(){var a=k.left,b=+k.top+p,c=a+l,d=b;return"M"+a+" "+b+" L "+c+" "+d});var u=d3.scale.linear().range([p,0]),v=d3.svg.axis().scale(u).orient("left").tickFormat(function(a){return d3.round(a*d3.max(f),0)});if(s.append("g").attr("class","y axis").attr("id","y_"+b).attr("text-anchor","end").attr("transform","translate( "+k.left+","+k.top+")").call(v).select(".domain"),s.append("g").append("text").attr("class","ax_title").attr("transform",function(){var a=d3.select("#y_"+b).node(),c=+k.left-a.getBoundingClientRect().width-5,d=+k.top+a.getBoundingClientRect().height/2-30,e="translate("+c+","+d+")rotate(-90)";return e}).text("Number of Jobs"),t.append("rect").attr("y",function(a){return p-a*q}).attr("height",function(a){return a*q}).attr("width",m-1),"hours"==c){t.append("line").attr("x1",0).attr("y1",0).attr("x2",0).attr("y2",3).attr("stroke","black").attr("stroke-width",1).attr("pointer-events","none").attr("transform",function(){return"translate( "+m/2+", "+p+")"}),t.append("text").attr("fill","rgb(0,0,0)").attr("transform","translate( 10, "+(p+10)+" )").text(function(a,b){var c="0000";return c=g[b].getHours()<10?"0"+String(g[b].getHours()):g[b].getHours()});var w="",x=!1;t.append("line").attr("x1",0).attr("y1",0).attr("x2",0).attr("y2",function(a,b){var c=0;return g[b].getDate()!=w&&(x?c=20:(c=27,x=!0),w=g[b].getDate()),c}).attr("stroke","black").attr("stroke-width",1).attr("pointer-events","none").attr("transform",function(){return"translate( 0, "+p+")"}),w="",curr_day_text="",x=!1,t.append("text").attr("fill","rgb(0,0,0)").attr("pointer-events","none").text(function(a,b){var c="",d="en-us";return g[b].getDate()!=curr_day_text&&(c=String(g[b].toLocaleString(d,{month:"long"})),c+=" "+String(g[b].getDate()),curr_day_text=g[b].getDate()),c}).attr("transform",function(a,b){var c=p,d=d3.select(this).node().getBBox().width;return g[b].getDate()!=w&&(x?c+=18:(c+=26,x=!0),w=g[b].getDate()),"translate( "+(d+2)+", "+c+" )"})}else if("days"==c){t.append("line").attr("x1",0).attr("y1",0).attr("x2",0).attr("y2",3).attr("stroke","black").attr("stroke-width",1).attr("pointer-events","none").attr("transform",function(){return"translate( "+m/2+", "+p+")"}),t.append("text").attr("fill","rgb(0,0,0)").attr("transform","translate( 9, "+(p+10)+" )").text(function(a,b){var c="0000";return c=j[b].getDate()<10?"0"+String(j[b].getDate()):j[b].getDate()});var y="",x=!1;t.append("line").attr("x1",0).attr("y1",0).attr("x2",0).attr("y2",function(a,b){var c=0;return j[b].getMonth()!=y&&(x?c=20:(c=27,x=!0),y=j[b].getMonth()),c}).attr("stroke","black").attr("stroke-width",1).attr("pointer-events","none").attr("transform",function(){return"translate( 0, "+p+")"}),y="",curr_month_text="",x=!1,t.append("text").attr("fill","rgb(0,100,0)").attr("pointer-events","none").text(function(a,b){var c="",d="en-us";return j[b].getMonth()!=curr_month_text&&(c=String(j[b].toLocaleString(d,{month:"long"})),c+=" "+String(j[b].getFullYear()),curr_month_text=j[b].getMonth()),c}).attr("transform",function(a,b){var c=p,d=d3.select(this).node().getBBox().width;return j[b].getMonth()!=y&&(x?c+=18:(c+=26,x=!0),y=j[b].getMonth()),"translate( "+(d+2)+", "+c+" )"})}s.append("g").attr("class","tool_tip").append("rect"),s.select(".tool_tip").append("text"),("jc_dy_chart"==b||"jc_hr_chart"==b)&&d3.select("#"+b).attr("height",r*o).attr("width",n*o).style("cursor","default")})}function create_histogram(a,b,c){require(["d3"],function(){function d(){var a=d3.select(this).attr("class");a=a.split(" "),d3.selectAll("."+a[0]).filter("."+a[1]).style("cursor","zoom-in").transition().duration(750).attr("height",i).attr("width",k),d3.select(this).style("cursor","default").transition().duration(750).attr("height",i*f).attr("width",k*f)}for(var e=a,f=1.75,g={top:60,right:30,bottom:50,left:60},h=150,i=h+g.top+g.bottom,j=300,k=j+g.left+g.right,l=d3.scale.linear().domain([0,d3.max(e)]).range([0,j]),e=d3.layout.histogram().bins(l.ticks(20))(e),m=[],n=0;n<e.length;n++)m.push(e[n].length);if(0!=d3.max(e))var o=h/d3.max(m);else var o=1;var p=d3.scale.linear().domain([0,d3.max(e,function(a){return a.y})]).range([h,0]),q=function(a){return hours=Math.floor(a/60),minutes=Math.floor(a-60*hours),hours<10&&(hours="0"+hours),minutes<10&&(minutes="0"+minutes),hours+":"+minutes},r=d3.select("#"+b).attr("viewBox","0 0 "+k+" "+i).attr("width",k).attr("height",i).attr("preserveAspectRatio","xMidYMin").on("click",d);r.append("g").append("text").attr("class","title").attr("transform",function(){return"translate( "+j+",15 )"}).text(c);var s,t=r.selectAll(".bar").data(e).enter().append("g").attr("class","bar").attr("transform",function(a){return"translate("+(+l(a.x)+ +g.left)+","+(+p(a.y)+ +g.top)+")"}).on("mouseenter",function(a){for(n=0,size=a.length;size>=1;)size/=10,n++;var b=4*n+10;d3.select(d3.event.path[1]).select(".tool_tip").select("text").attr("transform","translate( "+(g.left-5)+", "+(h-a.length*o+ +g.top+10)+" )").attr("visibility","visible").text(a.length),d3.select(d3.event.path[1]).select(".tool_tip").attr("width",b+"px").attr("height","15px").select("rect").attr("transform","translate( "+(+g.left-b)+", "+(h-a.length*o+ +g.top)+" )").attr("width",b+"px").attr("height","15px").attr("fill","#ebd9b2")}).on("mouseleave",function(){d3.select(d3.event.path[1]).select(".tool_tip").select("text").attr("visibility","hidden"),d3.select(d3.event.path[1]).select(".tool_tip").select("rect").attr("width","0").attr("height","0").attr("fill","")});s=void 0==e[0]?1:l(e[0].dx),t.append("rect").attr("x",1).attr("width",s-1).attr("height",function(a){return h-p(a.y)});var u=d3.svg.axis().scale(l).orient("bottom").tickFormat(q);r.append("g").attr("class","x axis").attr("id","x_"+b).attr("transform","translate( "+g.left+","+(+h+ +g.top)+")").call(u),r.append("g").append("text").attr("class","ax_title").attr("transform",function(){var a=d3.select("#x_"+b).node(),c=+g.left+a.getBoundingClientRect().width/2+30,d=+g.top+h+a.getBoundingClientRect().height+10,e="translate("+c+","+d+")";return e}).text("ETA - hrs:mins");var v=d3.svg.axis().scale(p).orient("left");r.append("g").attr("class","y axis").attr("id","y_"+b).attr("transform","translate( "+g.left+","+g.top+")").call(v),r.append("g").append("text").attr("class","ax_title").attr("transform",function(){var a=d3.select("#y_"+b).node(),c=+g.left-a.getBoundingClientRect().width-5,d=+g.top+a.getBoundingClientRect().height/2-30,e="translate("+c+","+d+")rotate(-90)";return e}).text("Number of Jobs"),r.append("g").attr("class","tool_tip").append("rect"),r.select(".tool_tip").append("text")})}setTimeout(refresh,6e4);
//# sourceMappingURL=../../maps/reports_webapp/run_stats.js.map