import React, { useState } from 'react'
import SearchEvents from './SearchEvents';
import '../assests/css/ToolBar.css'
import 'bootstrap/dist/css/bootstrap.min.css';
const ToolBar = (props)=>{
  const [modal , setModal] = useState(false);
  const toggle = () =>{setModal(!modal)};
  return (
    <div className='toolbar'>
      <SearchEvents modal={modal} toggle={toggle} props={props} />
      <div className='search' onClick={toggle}>
        <p>Search</p>
      </div>
      <div className='patient-zero'>
        <p>Patient Zero</p>
      </div>
      <div className='elastic'>
        <p>Elastic</p>
      </div>
    </div>
  )
}

export default ToolBar;