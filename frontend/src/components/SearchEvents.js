import React, { useState } from 'react'
import {Button,Modal,ModalHeader,ModalBody,ModalFooter,Form,FormGroup,Label,Input,Col,Spinner} from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import axios from 'axios';
import { API_URL, DEBUG } from '../constants';



export default function SearchEvents({modal,toggle,props}) {
  const [username,setUsername] = useState(null);
  const [ip,setIp] = useState(null);
  const [dateStart,setDateStart] = useState(null);
  const [dateEnd,setDateEnd] = useState(null);
  const [event,setEvent] = useState(null);
  const [loading,setLoading] = useState(false);
  const [searchingData,setSeachingData] = useState(null);
  const search = async ()=> {
    await axios.get(`${API_URL[DEBUG]}search`,{params:{
      event_code:event,
      username:username,
      ip_address:ip,
      event_date_start:dateStart,
      event_date_end:dateEnd
  }}).then(
      res=>{
        console.log("searching data: ",res.data);
        setSeachingData(res.data);
        setLoading(false);
      }
    ).catch(
      err =>{console.log(err)}
    )
  }

  return (
    <>
    {searchingData?
    <Modal isOpen={searchingData} toggle={toggle} fullscreen>
    <ModalHeader toggle={toggle}>Searching Results</ModalHeader>
    <ModalBody>
      <div>
      <p>{JSON.stringify(searchingData,undefined,40)}</p>
      </div>
    </ModalBody>
    <ModalFooter>
      <Button color="primary" onClick={()=>{setSeachingData(null)}}>
        Back
      </Button>{' '}
      <Button color="secondary" onClick={toggle}>
        Cancel
      </Button>
    </ModalFooter>
  </Modal>
    :
    <Modal isOpen={modal} toggle={toggle} {...props} fullscreen={"lg"} size='lg'> 
    <ModalHeader 
      toggle={toggle} 
      style={{
        "color":"#0457A6",
      }}
    >
    Events ID Search
    </ModalHeader>
    <ModalBody>
      {loading?<Spinner/>
      :
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
                    placeholder="Username you search for"
                    type="Text"
                    onChange={(e)=>{setUsername(e.target.value)}}
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
                    placeholder="ip address (Ipv4 or Ipv6) you search for"
                    type="Text"
                    onChange={(e)=>{setIp(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
            <Label 
                for="Datetimestart"
                sm={2}
            >
            Starting Datetime
            </Label>
            <Col sm={10}>
            <Input
            id="Datetimestart"
            name="datetimestart"
            placeholder="start datetime for searching of format 'YYYY-MM-DD HH:MM:SS:ZZZ'"
            type="datetime"
            onChange={(e)=>{setDateStart(e.target.value)}}
            />
            </Col>
        </FormGroup>
        <FormGroup row>
            <Label 
                for="Datetimeend"
                sm={2}
            >
            Ending Datetime
            </Label>
            <Col sm={10}>
            <Input
            id="Datetimend"
            name="datetimeend"
            placeholder="end datetime for searching of format 'YYYY-MM-DD HH:MM:SS:ZZZ'"
            type="datetime"
            onChange={(e)=>{setDateEnd(e.target.value)}}
            />
            </Col>
        </FormGroup>
        <FormGroup row>
            <Label 
                for="EventID"
                sm={2}    
            >
            Number
            </Label>
            <Col sm={10}>
                <Input
                id="EventID"
                name="eventid"
                placeholder="winodws event log id"
                type="number"
                min={0}
                onChange={(e)=>{setEvent(e.target.value)}}
                />
            </Col>
        </FormGroup>
        </Form>
}
    </ModalBody>
    <ModalFooter>
      <Button color='primary' onClick={search} outline>
        Search
      </Button>{' '}
      <Button color="danger" onClick={toggle} outline>
        Cancel
      </Button>
    </ModalFooter>
    
  </Modal>
}
</>
  )
}
