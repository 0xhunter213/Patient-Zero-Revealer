import React, { useState } from 'react'
import SearchEvents from './SearchEvents';
import '../assests/css/ToolBar.css'
import 'bootstrap/dist/css/bootstrap.min.css';
import {MdPolicy} from "react-icons/md";
import {SiElasticsearch} from "react-icons/si"
import {PiDetectiveFill} from "react-icons/pi"
const ToolBar = (props)=>{
  const [modal , setModal] = useState(false);
  const toggle = () =>{setModal(!modal)};
  return (
    <div className='toolbar'>
      <SearchEvents modal={modal} toggle={toggle} props={props} />
      <div className='search' onClick={toggle}>
        <div style={{"width":"50px","height":"50px"}}>
          <MdPolicy size={"lg"} color='#07539D'/>
        </div>
        <p>Search</p>
      </div>
      <div className='patient-zero'>
        <div style={{"width":"50px","height":"50px"}}>
          <PiDetectiveFill size={"lg"} color='#07539D'/>
        </div>
        <p>Patient Zero</p>
      </div>
      <div className='elastic'>
      <div style={{"width":"50px","height":"50px"}}>
        <SiElasticsearch size={"lg"} color='#07539D'/>
      </div>
        <p>Elastic</p>
      </div>
    </div>
  )
}

export default ToolBar;