import React, { useState } from 'react'
import SearchEvents from './SearchEvents';
import '../assests/css/ToolBar.css'
import 'bootstrap/dist/css/bootstrap.min.css';
import {MdPolicy} from "react-icons/md";
import {SiElasticsearch} from "react-icons/si"
import {PiDetectiveFill} from "react-icons/pi"
import PatientZero from './PatientZero';
import ElasticConnection from './ElasticConnection';
const ToolBar = (data,setData,props)=>{
  const [modal , setModal] = useState(false);
  const [pzmodal,setPzModal] = useState(false);
  const [esmodal,setEsmodal]=useState(false);
  const toggle = () =>{setModal(!modal)};
  const pztoggle= () =>{setPzModal(!pzmodal)};
  const estoggle = ()=>{setEsmodal(!esmodal)};
  return (
    <div className='toolbar'>
      <SearchEvents modal={modal} toggle={toggle} props={props} />
      <div className='search' onClick={toggle}>
        <div style={{"width":"50px","height":"50px"}}>
          <MdPolicy size={"lg"} color='#07539D'/>
        </div>
        <p>Search</p>
      </div>
      <PatientZero modal={pzmodal} toggle={pztoggle}  data={data} setData={setData}/>
      <div className='patient-zero' onClick={pztoggle}>
        <div style={{"width":"50px","height":"50px"}}>
          <PiDetectiveFill size={"lg"} color='#07539D'/>
        </div>
        <p>Patient Zero</p>
      </div>
      <ElasticConnection modal={esmodal} toggle={estoggle} props={props}/>
      <div className='elastic' onClick={estoggle}>
      <div style={{"width":"50px","height":"50px"}}>
        <SiElasticsearch size={"lg"} color='#07539D'/>
      </div>
        <p>Elastic</p>
      </div>
    </div>
  )
}

export default ToolBar;