
import './App.css';
import SideBar from './components/SideBar';
import ToolBar from './components/ToolBar';
import NetView from './components/NetView';
import { useState,useEffect} from 'react';
import { API_URL, DEBUG } from './constants';
import axios from "axios";
//["FFFFFF","0457A6","07539D","FFFFFF","162360"]
function App() {
  const [selected,setSelected] = useState(false);
  const [data,setData] = useState({nodes:[],edges:[]});
  const fetchData = async () =>{
    await axios.get(`${API_URL[DEBUG]}`).then(
      response =>{
        let nodes = response.data.nodes.filter((val,id,array) => {return array.indexOf(val) == id;})
        let edges = response.data.edges
        if(nodes.length != 0){
          nodes.forEach(element => {
            edges.push({from:element.id,to:"elastic",color:"green"})
          });
          
          nodes.push( {
                    id:"elastic",
                    shape:"image",
                    label:"elastic",
                    title:"elastic",
                    image:"https://companieslogo.com/img/orig/ESTC-4d81ee09.png",
                    size:40,
                  }
          )
         
        }
        
        setData({nodes:nodes?nodes:[],edges:edges?edges:[]})
        console.log("data",data)
      }
    ).catch(e=>{
      setData(data)
    })
  }
  useEffect(()=>{
    fetchData()
  },[data])

  return (
    <div className="App">
        <SideBar selected={selected} setSelected={setSelected}/>
        <NetView selected={selected} setSelected={setSelected} data={data} setData={setData}/>
        <ToolBar  data={data} setData={setData}/>

    </div>
  );
}

export default App;
