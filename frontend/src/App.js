
import './App.css';
import SideBar from './components/SideBar';
import ToolBar from './components/ToolBar';
import NetView from './components/NetView';
import { useState,useEffect } from 'react';

//["FFFFFF","0457A6","07539D","FFFFFF","162360"]
function App() {
  const [selected,setSelected] = useState(false);
  const [networkData,setNetworkData] = useState(null) 
  const fetchData = async()=>{
    await fetch("")
  } 
  useEffect()
  return (
    <div className="App">
        <SideBar selected={selected} setSelected={setSelected}/>
        <NetView selected={selected} setSelected={setSelected}/>
        <ToolBar/>

    </div>
  );
}

export default App;
