
import './App.css';
import SideBar from './components/SideBar';
import ToolBar from './components/ToolBar';
import NetView from './components/NetView';
//["FFFFFF","0457A6","07539D","FFFFFF","162360"]
function App() {
  return (
    <div className="App">
        <SideBar/>
        <NetView/>
        <ToolBar/>

    </div>
  );
}

export default App;
