import React, { useState, useMemo } from 'react';
import { Layout, message, Empty } from 'antd';
import { Allotment } from "allotment";
import "allotment/dist/style.css";
import Toolbar from './components/Toolbar';
import PacketList from './components/PacketList';
import PacketDetail from './components/PacketDetail';
import { uploadPcap, getPacketDetail as apiGetPacketDetail } from './api';
import 'antd/dist/reset.css';
import './App.css';

const { Header, Content, Footer } = Layout;

const App = () => {
  const [packets, setPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [packetDetail, setPacketDetail] = useState(null);
  const [filename, setFilename] = useState('');
  const [sortInfo, setSortInfo] = useState({});
  const [undoCount, setUndoCount] = useState(0);
  const [redoCount, setRedoCount] = useState(0);

  const handleUpload = async (file) => {
    try {
      const response = await uploadPcap(file);
      setFilename(response.data.filename);
      setPackets(response.data.packets);
      setUndoCount(response.data.undo_count);
      setRedoCount(response.data.redo_count);
      setSelectedPacket(null);
      setPacketDetail(null);
      message.success(`${response.data.filename} uploaded successfully`);
    } catch (error) {
      message.error('File upload failed');
    }
  };

  const handleSelectPacket = async (packet, highlightRange = null) => {
    setSelectedPacket(packet);
    try {
      const response = await apiGetPacketDetail(packet.id);
      const detailData = response.data;
      
      if (highlightRange) {
        detailData.highlight_range_on_load = highlightRange;
      }

      setPacketDetail(detailData);
    } catch (error) {
      message.error('Failed to fetch packet details');
      setPacketDetail(null);
    }
  };

  const handleDetailChange = (newDetail) => {
    setPacketDetail(newDetail);
    if (newDetail.summary) {
      setPackets(prevPackets => {
        const index = prevPackets.findIndex(p => p.id === newDetail.summary.id);
        if (index !== -1) {
          const newPackets = [...prevPackets];
          newPackets[index] = newDetail.summary;
          return newPackets;
        }
        return prevPackets;
      });
    }
  };

  const handlePacketsChange = (newPackets) => {
    setPackets(newPackets);
    if (selectedPacket && !newPackets.find(p => p.id === selectedPacket.id)) {
      setSelectedPacket(null);
      setPacketDetail(null);
    }
  };

  const handleUndoRedo = (undoRedoData) => {
    if (undoRedoData && undoRedoData.packets) {
      setPackets(undoRedoData.packets);
      setUndoCount(undoRedoData.undo_count);
      setRedoCount(undoRedoData.redo_count);

      if (selectedPacket) {
        const updatedPacket = undoRedoData.packets.find(p => p.id === selectedPacket.id);
        if (updatedPacket) {
          handleSelectPacket(updatedPacket, undoRedoData.highlight_range);
        } else {
          setSelectedPacket(null);
          setPacketDetail(null);
        }
      }
    }
  };

  const handleSort = (pagination, filters, sorter) => {
    setSortInfo(sorter);
  };

  const sortedPackets = useMemo(() => {
    if (sortInfo.order && sortInfo.field) {
      const sorted = [...packets].sort((a, b) => {
        const aValue = a[sortInfo.field];
        const bValue = b[sortInfo.field];
        
        let result = 0;
        if (typeof aValue === 'number' && typeof bValue === 'number') {
          result = aValue - bValue;
        } else {
          result = String(aValue).localeCompare(String(bValue));
        }

        return sortInfo.order === 'ascend' ? result : -result;
      });
      return sorted;
    }
    return packets;
  }, [packets, sortInfo]);

  return (
    <Layout style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header>
        <div style={{ color: 'white', fontSize: '24px' }}>Pcap Editor</div>
      </Header>
      <Content style={{ padding: '20px 50px', display: 'flex', flexDirection: 'column', flex: '1 1 auto', overflow: 'hidden' }}>
        <Toolbar 
          onUpload={handleUpload} 
          filename={filename} 
          onUndoRedo={handleUndoRedo} 
          undoCount={undoCount} 
          redoCount={redoCount} 
        />
        
        <div style={{ flex: '1 1 auto', minHeight: 0, marginTop: '20px', border: '1px solid #f0f0f0' }}>
          {packets.length > 0 ? (
            <Allotment vertical>
              <Allotment.Pane>
                <div style={{ height: '100%', overflow: 'auto' }}>
                  <PacketList 
                    packets={sortedPackets}
                    onSelectPacket={handleSelectPacket} 
                    selectedPacketId={selectedPacket?.id}
                    onSort={handleSort}
                    onPacketsChange={handlePacketsChange}
                  />
                </div>
              </Allotment.Pane>
              <Allotment.Pane>
                <PacketDetail
                  packet={selectedPacket}
                  detail={packetDetail}
                  onDetailChange={handleDetailChange}
                />
              </Allotment.Pane>
            </Allotment>
          ) : (
            <div style={{ height: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center', background: '#f0f2f5' }}>
              <Empty description="Please upload a pcap file to begin." />
            </div>
          )}
        </div>

      </Content>
      <Footer style={{ textAlign: 'center', flexShrink: 0 }}>
        Pcap Editor ©2025 Created by GitHub Copilot
      </Footer>
    </Layout>
  );
};

export default App;



