import React from 'react'
import {Button,Modal,ModalHeader,ModalBody,ModalFooter,Form,FormGroup,Label,Input,Col} from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';



export default function SearchEvents({modal,toggle,props}) {
  return (
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
            placeholder="datetime of format 'YYYY-MM-DD HH:MM:SS:ZZZ'"
            type="datetime"
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
                />
            </Col>
        </FormGroup>
        </Form>

    </ModalBody>
    <ModalFooter>
      <Button color='primary' onClick={toggle} outline>
        Search
      </Button>{' '}
      <Button color="danger" onClick={toggle} outline>
        Cancel
      </Button>
    </ModalFooter>
    
  </Modal>
  )
}
