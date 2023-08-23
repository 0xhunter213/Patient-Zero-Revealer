
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
  const [data,setData] = useState(null);
  const fetchData = async () =>{
    await axios.get(`${API_URL[DEBUG]}`).then(
      response =>{
        let nodes = response.data.nodes.filter((val,id,array) => {return array.indexOf(val) == id;})
        let edges = response.data.edges
        setData({nodes:nodes?nodes:[],edges:edges?edges:[]})
      }
    ).catch(e=>{
      setData(data)
    })
  }
  useEffect(()=>{
    fetchData()
  },[])

  return (
    <div className="App">
        <SideBar selected={selected} setSelected={setSelected}/>
        <NetView selected={selected} setSelected={setSelected} data={data} setData={setData}/>
        <ToolBar props={{data:data,setData:setData}}/>

    </div>
  );
}

export default App;
