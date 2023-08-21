import React,{useState,useRef,useEffect} from 'react'
import Network from "react-graph-vis";
import "../assests/css/NetView.css"
import Grid from "@mui/material/Grid";
import { API_URL, DEBUG } from '../constants';
import axios from "axios";
export default function NetView({selected,setSelected,props}) {
    const graphRef = useRef(null);
    const [datas, setDatas] = useState("--");
    const [data,setData] = useState(null);
    const WindowsImg = "https://cdn.icon-icons.com/icons2/595/PNG/512/Computer_icon-icons.com_55509.png";
    const elasticImg = "https://companieslogo.com/img/orig/ESTC-4d81ee09.png";
   const _data = {
      nodes: [
        {
          id:"elastic",
          shape:"image",
          label:"elastic",
          title:"elastic",
          image:"https://companieslogo.com/img/orig/ESTC-4d81ee09.png",
          size:40,
        }
        ,
        {
          id: "MACHINE0",
          color: "blue",
          shape: "image",
          label: "machine0",
          title: "machine0",
          image:
            "https://cdn.icon-icons.com/icons2/595/PNG/512/Computer_icon-icons.com_55509.png",
          size: 40,
          ip:"10.10.14.34",
          build:"19.345",
          os:"Windows 10",
          domain:"$MACHINE0",


        },
        {
          id: "MACHINE1",
          color: "blue",
          shape: "image",
          title: "machine1",
          label: "machine1",
          image:
            "https://cdn.icon-icons.com/icons2/595/PNG/512/Computer_icon-icons.com_55509.png",
          size: 40,
          ip:"10.10.14.35",
          build:"19.391",
          os:"Windows 10",
          domain:"$MACHINE1",
          
        },
  
      ],
      edges: [
        { from: "MACHINE0", to: "MACHINE1", color: "red" },
        { from: "MACHINE1", to: "MACHINE0", color: "red" },
        { from: "MACHINE0", to: "elastic", color: "green" },
        { from: "MACHINE1", to: "elastic", color: "green" },
      
      ]
    };
  
  //   console.log(_data)
    //const [networkData,setNetworkData] = useState(null) 

    const options = {
      physics: {
        stabilization: false,
      },
      nodes: {
        color: "#53BF9D",
      },
      edges: {
        physics: false,
        color: "#233b91",
        arrows: {
          to: {
            enabled: true,
            type: "arrow",
          },
  
          from: {
            enabled: true,
            type: "arrow",
          },
        },
        length: 200,
      },

    };
    function myFunction() {
      // Code for your onclick function goes here
      console.log("Icon image clicked!");
    }
    const handleZoomIn = () => {
      if (graphRef.current) {
        // graphRef.current.zoomIn();
      }
    };
    const handleNodeClick = (event) => {
      console.log("click event is happened");
      console.log("click event is happened in handlenode click");
      console.log(event);
      if(event.nodes[0]){
        setSelected(data.nodes.find(({id})=> id === event.nodes[0]));
        console.log(selected)
      }else{
        setSelected(false)
      }
      };
  
    // Function to zoom out
    const handleZoomOut = () => {
      if (graphRef.current) {
        // graphRef.current.zoomOut();
      }
    };
    const fetchData = async () =>{
      await axios.get(`${API_URL[DEBUG]}`).then(
        response =>{
          setData({nodes:response.data.nodes?response.data.nodes:[],edges:response.data.edges?response.data.edges:[]})
        }
      )
    }
    useEffect(()=>{
      fetchData()
    },[data])

    return(
    <div className='topology'>
      {data?
      <Grid>
        <Grid item md={7} style={{ display: "flex" }}>
          <Network
            graph={data}
            ref={graphRef}
            options={options}
            events={{
              click: handleNodeClick
            }}
            // getNetwork={(network) => {
            //   network.on("afterDrawing", (ctx) => {
            //     data.nodes.forEach((node) => {
            //       const iconImg = new Image();
            //       iconImg.src =
            //         "https://www.iconarchive.com/download/i22783/kyo-tux/phuzion/Sign-Info.ico";
            //       const nodeId = node.id;
            //       const nodePosition = network.getPositions([nodeId])[nodeId];
            //       const nodeSize = 20;
            //       var setVal = sessionStorage.getItem("set");
            //       if (setVal === "yes") {
            //         console.log(setVal);
            //         ctx.font = "14px Arial";
            //         ctx.fillStyle = "#000000";
            //         ctx.textAlign = "center";
            //         ctx.shadowColor = "rgba(0, 0, 0, 0.5)";
            //         ctx.shadowBlur = 5;
            //         ctx.fillStyle = "#ffcc00";
            //         ctx.fillRect(
            //           nodePosition.x + nodeSize + 2,
            //           nodePosition.y + nodeSize - 20,
            //           50,
            //           20
            //         );
            //         ctx.fillText(
            //           node.label,
            //           nodePosition.x,
            //           nodePosition.y + nodeSize + 20
            //         );
            //         ctx.font = "12px Arial";
            //         ctx.color = "black";
            //         ctx.fillStyle = "black";
            //         ctx.textAlign = "left";
            //         ctx.fillText(
            //           node.cost,
            //           nodePosition.x + nodeSize + 5,
            //           nodePosition.y + nodeSize - 5
            //         );
            //       } else if (setVal === "no") {
            //         console.log(setVal);
            //         const iconWidth = 20; // width of the icon image
            //         const iconHeight = 16;
            //         iconImg.src =
            //           "https://www.iconarchive.com/download/i22783/kyo-tux/phuzion/Sign-Info.ico";
            //         ctx.font = "14px Arial";
            //         ctx.fillStyle = "#000000";
            //         ctx.textAlign = "center";
            //         ctx.shadowColor = "rgba(0, 0, 0, 0.5)";
            //         ctx.shadowBlur = 5;
            //         ctx.fillStyle = "#ffcc00";
            //         ctx.drawImage(
            //           iconImg,
            //           nodePosition.x + nodeSize + 5,
            //           nodePosition.y + nodeSize + 5,
            //           iconWidth,
            //           iconHeight
            //         );
            //         iconImg.addEventListener("mouseover", myFunction, "false");
            //       }
            //     });
            //   });
            // }}
            style={{ display: "flex", height: "40rem" }}
          />
        </Grid>
        {/* <Grid
          item
          md={12}
          style={{ display: "flex", justifyContent: "space-around" }}
        >
          <Button
            variant="contained"
            onClick={(e) => {
              sessionStorage.setItem("set", "yes");
              graphRef.current.updateGraph();
            }}
          >
            Price Tagger
          </Button>
          <Button
            variant="contained"
            onClick={(e) => {
              sessionStorage.setItem("set", "no");
              graphRef.current.updateGraph();
            }}
          >
            Cura
          </Button>
          <Button
            variant="contained"
            onClick={() => {
              console.log(data, "hujhgh");
              console.log(JSON.stringify(data), "########");
              const jsonString = JSON.stringify(data, null, 2); // Using null, 2 for pretty formatting

              // Create a Blob from the JSON string
              const blob = new Blob([jsonString], { type: "application/json" });

              // Create a URL for the Blob
              const url = URL.createObjectURL(blob);

              // Create a link element to download the JSON file
              const link = document.createElement("a");
              link.href = url;
              link.download = "data.json";
              document.body.appendChild(link);
              link.click();

              // Clean up by revoking the URL and removing the link element
              URL.revokeObjectURL(url);
              document.body.removeChild(link);
            }}
          >
            Fetch updated data
          </Button>
        </Grid>
      </Grid> */}
      </Grid>:
      <div className='networkError'><h1>Elastic Connection settings needed</h1></div>}
    </div>
  )
}
