import React, { useState } from 'react'
import {Button,Modal,ModalHeader,ModalBody,ModalFooter,Form,FormGroup,Label,Input,Col,Spinner,Alert} from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import axios from 'axios';
import { API_URL,DEBUG } from '../constants';
export default function PatientZero({modal,toggle,props}) {
  const [username,setUsername] = useState(null);
  const [ip,setIp] = useState(null);
  const [date,setDate] = useState(null);
  const [loading,setLoading] = useState(false);
  const [err,setErr] = useState(false);
  const [info,setInfo] = useState(false);
  const [message,setMessage] = useState("");

  const onDismiss = () => setErr(false);
  const infoToggle = () => setInfo(false);
  const pzeroDetection = async ()=>{
    await axios.get(`${API_URL[DEBUG]}pzero`,{params:{
      username:username,
      ip_address:ip,
      timestamp:date}
    }).then(
      res=>{
        if(res.data.message){
          setLoading(false);
          setInfo(true);
          setMessage(res.data.message);
          setTimeout(infoToggle,5000);
        }else{
        let data = props.data;
        console.log("pzero api data: ",res.data);
        data.filter((val,id) => {
          if(id == res.data.id){
            // change image to be compromised
            val.infected_first = true;
            val.image = "https://raw.githubusercontent.com/MEhrn00/Havoc/blob/main/client/Data/resources/win10-8-icon-high.png"
          }
        });

        props.setData(data);
        setLoading(false)
        toggle();
      }
      }
    ).catch(
      e => {
        setLoading(false);
        setErr(true);
      }
    );
  }
  const detect = ()=>{
    if (username){
      setLoading(true);
      pzeroDetection();
    }
  }
  return (
    <Modal isOpen={modal} toggle={toggle} {...props} fullscreen={"lg"} size='lg'> 
    <ModalHeader 
      toggle={toggle} 
      style={{
        "color":"#0457A6",
      }}
    >
    Patient Zero Detection
    </ModalHeader>
    <ModalBody>
      {loading?
      <div style={{
        display:'flex',
        justifyContent:'center',
        padding:50,
      }}>
        <Spinner/>
      </div>
      :
        <>
        <Alert color="danger" isOpen={err} toggle={onDismiss}>
            Somthing goes wrong !
        </Alert>
        <Alert color='info' isOpen={info} toggle={infoToggle}>
          {message}
        </Alert>
        <Form>
            <FormGroup row>
                <Label
                for="Username"
                sm={2}
                >
                Username
                </Label>
                <Col sm={10}>
                <Input
                    id="Username"
                    name="Username"
                    placeholder="Username (required)"
                    type="Text"
                    onChange={(e)=> {setUsername(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
                <Label
                for="ipaddress"
                sm={2}
                >
                Ip address                 
                </Label>
                <Col sm={10}>
                <Input
                    id="ipaddress"
                    name="ipaddress"
                    placeholder="ip address Ipv4 or Ipv6 (optional)"
                    type="Text"
                    onChange={(e)=>{setIp(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
            <Label 
                for="Datetime"
                sm={2}
            >
            Datetime
            </Label>
            <Col sm={10}>
            <Input
            id="Datetime"
            name="datetime"
            placeholder="datetime 'YYYY-MM-DD HH:MM:SS:ZZZ' (optional)"
            type="datetime"
            onChange={(e)=>{setDate(e.target.value)}}
            />
            </Col>
        </FormGroup>
        </Form>
        </>}
    </ModalBody>
    <ModalFooter>
      <Button color='primary' onClick={detect} outline>
        Detect
      </Button>{' '}
      <Button color="danger" onClick={toggle} outline>
        Cancel
      </Button>
    </ModalFooter>
    
  </Modal>
  )
}
