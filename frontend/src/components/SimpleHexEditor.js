import React, { useState, useEffect, useRef } from 'react';
import './SimpleHexEditor.css';

const HexByte = ({ byte, offset, isHighlighted, isSelected, onSelect, onUpdate }) => {
  const [isEditing, setIsEditing] = useState(false);
  const [editValue, setEditValue] = useState('');
  const inputRef = useRef(null);

  const hexString = byte.toString(16).padStart(2, '0').toUpperCase();

  useEffect(() => {
    if (!isSelected) {
      setIsEditing(false);
    }
  }, [isSelected]);

  useEffect(() => {
    if (isEditing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [isEditing]);

  const handleDoubleClick = () => {
    if (isSelected) {
      setIsEditing(true);
      setEditValue(hexString);
    }
  };

  const handleClick = () => {
    onSelect(offset);
  };

  const handleInputChange = (e) => {
    const value = e.target.value.toUpperCase().replace(/[^0-9A-F]/g, '').slice(0, 2);
    setEditValue(value);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleUpdate();
    } else if (e.key === 'Escape') {
      setIsEditing(false);
      setEditValue('');
    }
  };

  const handleUpdate = () => {
    if (editValue.length === 2 && editValue !== hexString) {
      onUpdate(offset, parseInt(editValue, 16));
    }
    setIsEditing(false);
  };

  const className = `hex-byte ${isHighlighted ? 'highlighted' : ''} ${isSelected ? 'selected' : ''}`;

  if (isEditing && isSelected) {
    return (
      <input
        ref={inputRef}
        type="text"
        value={editValue}
        onChange={handleInputChange}
        onKeyDown={handleKeyDown}
        onBlur={handleUpdate}
        className="hex-input"
        maxLength={2}
      />
    );
  }

  return (
    <span
      className={className}
      onClick={handleClick}
      onDoubleClick={handleDoubleClick}
      title={`Offset: ${offset}`}
    >
      {hexString}
    </span>
  );
};

const SimpleHexEditor = ({ data, onHexChange, highlight }) => {
  const [selectedOffset, setSelectedOffset] = useState(null);
  const bytes = new Uint8Array(data);

  const handleSelect = (offset) => {
    setSelectedOffset(offset);
  };

  const handleUpdateByte = (offset, newByteValue) => {
    const newBytes = new Uint8Array(bytes);
    newBytes[offset] = newByteValue;
    const newHexString = Array.from(newBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    onHexChange(newHexString);
  };

  const renderBytes = () => {
    const elements = [];
    for (let i = 0; i < bytes.length; i++) {
      const isHighlighted = i >= highlight.start && i < highlight.end;
      const isSelected = i === selectedOffset;
      elements.push(
        <HexByte
          key={i}
          byte={bytes[i]}
          offset={i}
          isHighlighted={isHighlighted}
          isSelected={isSelected}
          onSelect={handleSelect}
          onUpdate={handleUpdateByte}
        />
      );
      if ((i + 1) % 16 === 0 && i < bytes.length -1) {
        elements.push(<br key={`br-${i}`} />);
      }
    }
    return elements;
  };

  const renderAscii = () => {
    const elements = [];
    for (let i = 0; i < bytes.length; i++) {
      const char = bytes[i] >= 32 && bytes[i] <= 126 ? String.fromCharCode(bytes[i]) : '.';
      const isHighlighted = i >= highlight.start && i < highlight.end;
      const isSelected = i === selectedOffset;
      elements.push(
        <span key={i} className={`ascii-char ${isHighlighted ? 'highlighted' : ''} ${isSelected ? 'selected' : ''}`}>
          {char}
        </span>
      );
       if ((i + 1) % 16 === 0 && i < bytes.length -1) {
        elements.push(<br key={`br-ascii-${i}`} />);
      }
    }
    return elements;
  };

  const renderOffsets = () => {
    const elements = [];
    for (let i = 0; i < bytes.length; i += 16) {
      elements.push(
        <div key={i} className="offset-label">
          {i.toString(16).padStart(8, '0')}
        </div>
      );
    }
    return elements;
  };

  if (bytes.length === 0) {
    return <div className="hex-editor-container empty">No Hex data available for this packet.</div>;
  }

  return (
    <div className="hex-editor-container">
      <div className="offset-column">{renderOffsets()}</div>
      <div className="hex-column">{renderBytes()}</div>
      <div className="ascii-column">{renderAscii()}</div>
    </div>
  );
};

export default SimpleHexEditor;
