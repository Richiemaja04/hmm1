# app/core/feature_extractor.py
"""
Advanced feature extraction for keystroke and mouse behavioral biometrics
Extracts 40 features (20 keystroke + 20 mouse) from user interaction data
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import math
from scipy import stats
from collections import defaultdict, deque

class BehavioralFeatureExtractor:
    """Extract behavioral biometric features from user input data"""
    
    def __init__(self):
        self.keystroke_features = [
            'mean_key_hold_time', 'std_key_hold_time', 'mean_flight_time', 'std_flight_time',
            'typing_speed_wpm', 'typing_speed_variance', 'backspace_frequency', 'delete_frequency',
            'shift_key_usage', 'enter_key_usage', 'arrow_key_usage', 'digraph_latency_mean',
            'trigraph_latency_mean', 'error_correction_rate', 'capitalization_method_ratio',
            'punctuation_frequency', 'word_count', 'special_char_frequency', 'numeric_keypad_usage',
            'session_typing_rhythm'
        ]
        
        self.mouse_features = [
            'avg_mouse_speed', 'peak_mouse_speed', 'avg_mouse_acceleration', 'movement_curvature',
            'movement_jitter', 'path_straightness', 'pause_count', 'avg_pause_duration',
            'click_rate', 'double_click_frequency', 'right_click_frequency', 'click_duration_mean',
            'scroll_speed_mean', 'scroll_direction_ratio', 'drag_drop_count', 'avg_drag_distance',
            'hover_duration_mean', 'idle_time_ratio', 'movement_angle_entropy', 'wheel_click_frequency'
        ]
    
    def extract_keystroke_features(self, keystroke_events: List[Dict]) -> Dict[str, float]:
        """Extract 20 keystroke behavioral features"""
        if not keystroke_events:
            return {feature: 0.0 for feature in self.keystroke_features}
        
        features = {}
        
        # Convert to DataFrame for easier processing
        df = pd.DataFrame(keystroke_events)
        if df.empty:
            return {feature: 0.0 for feature in self.keystroke_features}
        
        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Basic timing features
        hold_times = []
        flight_times = []
        
        # Calculate hold times (key down to key up)
        for _, event in df.iterrows():
            if event.get('type') == 'keydown':
                key_up_event = df[(df['key'] == event['key']) & 
                                (df['type'] == 'keyup') & 
                                (df['timestamp'] > event['timestamp'])].head(1)
                if not key_up_event.empty:
                    hold_time = (key_up_event.iloc[0]['timestamp'] - event['timestamp']).total_seconds() * 1000
                    if 0 < hold_time < 1000:  # Reasonable bounds
                        hold_times.append(hold_time)
        
        # Calculate flight times (key up to next key down)
        keydown_events = df[df['type'] == 'keydown'].sort_values('timestamp')
        for i in range(len(keydown_events) - 1):
            current_time = keydown_events.iloc[i]['timestamp']
            next_time = keydown_events.iloc[i + 1]['timestamp']
            flight_time = (next_time - current_time).total_seconds() * 1000
            if 0 < flight_time < 2000:  # Reasonable bounds
                flight_times.append(flight_time)
        
        # Feature 1-2: Hold time statistics
        features['mean_key_hold_time'] = np.mean(hold_times) if hold_times else 0.0
        features['std_key_hold_time'] = np.std(hold_times) if len(hold_times) > 1 else 0.0
        
        # Feature 3-4: Flight time statistics
        features['mean_flight_time'] = np.mean(flight_times) if flight_times else 0.0
        features['std_flight_time'] = np.std(flight_times) if len(flight_times) > 1 else 0.0
        
        # Feature 5-6: Typing speed and variance
        total_chars = len(keydown_events)
        if len(keydown_events) > 1:
            time_span = (keydown_events.iloc[-1]['timestamp'] - keydown_events.iloc[0]['timestamp']).total_seconds()
            if time_span > 0:
                features['typing_speed_wpm'] = (total_chars / 5) / (time_span / 60)  # Standard WPM calculation
                
                # Calculate typing rhythm variance
                intervals = [(keydown_events.iloc[i+1]['timestamp'] - keydown_events.iloc[i]['timestamp']).total_seconds() 
                           for i in range(len(keydown_events)-1)]
                features['typing_speed_variance'] = np.var(intervals) if len(intervals) > 1 else 0.0
            else:
                features['typing_speed_wpm'] = 0.0
                features['typing_speed_variance'] = 0.0
        else:
            features['typing_speed_wpm'] = 0.0
            features['typing_speed_variance'] = 0.0
        
        # Feature 7-8: Error correction keys
        total_keys = len(df)
        backspace_count = len(df[df['key'].isin(['Backspace', 'Delete'])])
        features['backspace_frequency'] = backspace_count / total_keys if total_keys > 0 else 0.0
        features['delete_frequency'] = len(df[df['key'] == 'Delete']) / total_keys if total_keys > 0 else 0.0
        
        # Feature 9-11: Special key usage
        features['shift_key_usage'] = len(df[df['key'].isin(['Shift', 'ShiftLeft', 'ShiftRight'])]) / total_keys if total_keys > 0 else 0.0
        features['enter_key_usage'] = len(df[df['key'] == 'Enter']) / total_keys if total_keys > 0 else 0.0
        features['arrow_key_usage'] = len(df[df['key'].isin(['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'])]) / total_keys if total_keys > 0 else 0.0
        
        # Feature 12-13: Digraph and trigraph latencies
        features['digraph_latency_mean'] = self._calculate_ngraph_latency(keydown_events, 2)
        features['trigraph_latency_mean'] = self._calculate_ngraph_latency(keydown_events, 3)
        
        # Feature 14: Error correction rate
        features['error_correction_rate'] = self._calculate_error_correction_rate(df)
        
        # Feature 15: Capitalization method ratio
        features['capitalization_method_ratio'] = self._calculate_capitalization_ratio(df)
        
        # Feature 16: Punctuation frequency
        punctuation_keys = ['.', ',', '!', '?', ';', ':', '"', "'"]
        features['punctuation_frequency'] = len(df[df['key'].isin(punctuation_keys)]) / total_keys if total_keys > 0 else 0.0
        
        # Feature 17: Word count estimation
        space_count = len(df[df['key'] == ' '])
        features['word_count'] = space_count + 1 if space_count > 0 else 1
        
        # Feature 18: Special character frequency
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+']
        features['special_char_frequency'] = len(df[df['key'].isin(special_chars)]) / total_keys if total_keys > 0 else 0.0
        
        # Feature 19: Numeric keypad usage
        numeric_keys = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        features['numeric_keypad_usage'] = len(df[df['key'].isin(numeric_keys)]) / total_keys if total_keys > 0 else 0.0
        
        # Feature 20: Session typing rhythm consistency
        features['session_typing_rhythm'] = self._calculate_typing_rhythm(keydown_events)
        
        return features
    
    def extract_mouse_features(self, mouse_events: List[Dict]) -> Dict[str, float]:
        """Extract 20 mouse behavioral features"""
        if not mouse_events:
            return {feature: 0.0 for feature in self.mouse_features}
        
        features = {}
        
        # Convert to DataFrame
        df = pd.DataFrame(mouse_events)
        if df.empty:
            return {feature: 0.0 for feature in self.mouse_features}
        
        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Movement events only
        move_events = df[df['type'] == 'mousemove'].copy()
        if not move_events.empty:
            move_events = move_events.sort_values('timestamp')
            
            # Calculate velocities and accelerations
            velocities = []
            accelerations = []
            distances = []
            angles = []
            
            for i in range(1, len(move_events)):
                prev_event = move_events.iloc[i-1]
                curr_event = move_events.iloc[i]
                
                # Distance and time
                dx = curr_event['clientX'] - prev_event['clientX']
                dy = curr_event['clientY'] - prev_event['clientY']
                distance = math.sqrt(dx**2 + dy**2)
                time_diff = (curr_event['timestamp'] - prev_event['timestamp']).total_seconds()
                
                if time_diff > 0 and distance > 0:
                    velocity = distance / time_diff
                    velocities.append(velocity)
                    distances.append(distance)
                    
                    # Angle calculation
                    angle = math.atan2(dy, dx)
                    angles.append(angle)
                    
                    # Acceleration calculation
                    if i > 1 and len(velocities) > 1:
                        acceleration = (velocities[-1] - velocities[-2]) / time_diff
                        accelerations.append(acceleration)
        
        # Feature 1-2: Mouse speed statistics
        features['avg_mouse_speed'] = np.mean(velocities) if velocities else 0.0
        features['peak_mouse_speed'] = np.max(velocities) if velocities else 0.0
        
        # Feature 3: Average acceleration
        features['avg_mouse_acceleration'] = np.mean(np.abs(accelerations)) if accelerations else 0.0
        
        # Feature 4-5: Movement characteristics
        features['movement_curvature'] = self._calculate_curvature(move_events)
        features['movement_jitter'] = self._calculate_jitter(velocities)
        
        # Feature 6: Path straightness
        features['path_straightness'] = self._calculate_path_straightness(move_events)
        
        # Feature 7-8: Pause analysis
        pause_count, avg_pause_duration = self._analyze_pauses(move_events)
        features['pause_count'] = pause_count
        features['avg_pause_duration'] = avg_pause_duration
        
        # Feature 9-12: Click analysis
        click_events = df[df['type'].isin(['click', 'mousedown', 'mouseup'])]
        features['click_rate'] = len(click_events) / len(df) if len(df) > 0 else 0.0
        features['double_click_frequency'] = self._count_double_clicks(df) / len(df) if len(df) > 0 else 0.0
        features['right_click_frequency'] = len(df[df.get('button', 0) == 2]) / len(df) if len(df) > 0 else 0.0
        features['click_duration_mean'] = self._calculate_click_duration(df)
        
        # Feature 13-14: Scroll analysis
        scroll_events = df[df['type'] == 'wheel']
        features['scroll_speed_mean'] = self._calculate_scroll_speed(scroll_events)
        features['scroll_direction_ratio'] = self._calculate_scroll_direction_ratio(scroll_events)
        
        # Feature 15-16: Drag and drop
        features['drag_drop_count'] = self._count_drag_operations(df)
        features['avg_drag_distance'] = self._calculate_avg_drag_distance(df)
        
        # Feature 17: Hover duration
        features['hover_duration_mean'] = self._calculate_hover_duration(move_events)
        
        # Feature 18: Idle time ratio
        features['idle_time_ratio'] = self._calculate_idle_time_ratio(df)
        
        # Feature 19: Movement angle entropy
        features['movement_angle_entropy'] = self._calculate_angle_entropy(angles)
        
        # Feature 20: Wheel click frequency
        features['wheel_click_frequency'] = len(df[df.get('button', 0) == 1]) / len(df) if len(df) > 0 else 0.0
        
        return features
    
    # Helper methods for keystroke features
    def _calculate_ngraph_latency(self, keydown_events: pd.DataFrame, n: int) -> float:
        """Calculate n-graph latency (average time between n consecutive keys)"""
        if len(keydown_events) < n:
            return 0.0
        
        latencies = []
        for i in range(len(keydown_events) - n + 1):
            time_diff = (keydown_events.iloc[i + n - 1]['timestamp'] - 
                        keydown_events.iloc[i]['timestamp']).total_seconds() * 1000
            latencies.append(time_diff)
        
        return np.mean(latencies) if latencies else 0.0
    
    def _calculate_error_correction_rate(self, df: pd.DataFrame) -> float:
        """Calculate rate of error correction (backspace/delete usage patterns)"""
        correction_keys = ['Backspace', 'Delete']
        correction_events = df[df['key'].isin(correction_keys)]
        return len(correction_events) / len(df) if len(df) > 0 else 0.0
    
    def _calculate_capitalization_ratio(self, df: pd.DataFrame) -> float:
        """Calculate ratio of shift key usage to total typing"""
        shift_events = df[df['key'].isin(['Shift', 'ShiftLeft', 'ShiftRight'])]
        alpha_events = df[df['key'].str.match(r'^[a-zA-Z]$', na=False)]
        return len(shift_events) / len(alpha_events) if len(alpha_events) > 0 else 0.0
    
    def _calculate_typing_rhythm(self, keydown_events: pd.DataFrame) -> float:
        """Calculate consistency of typing rhythm"""
        if len(keydown_events) < 3:
            return 0.0
        
        intervals = []
        for i in range(1, len(keydown_events)):
            interval = (keydown_events.iloc[i]['timestamp'] - 
                       keydown_events.iloc[i-1]['timestamp']).total_seconds()
            intervals.append(interval)
        
        # Return coefficient of variation (lower = more consistent)
        if len(intervals) > 1 and np.mean(intervals) > 0:
            return np.std(intervals) / np.mean(intervals)
        return 0.0
    
    # Helper methods for mouse features
    def _calculate_curvature(self, move_events: pd.DataFrame) -> float:
        """Calculate path curvature"""
        if len(move_events) < 3:
            return 0.0
        
        curvatures = []
        for i in range(1, len(move_events) - 1):
            p1 = (move_events.iloc[i-1]['clientX'], move_events.iloc[i-1]['clientY'])
            p2 = (move_events.iloc[i]['clientX'], move_events.iloc[i]['clientY'])
            p3 = (move_events.iloc[i+1]['clientX'], move_events.iloc[i+1]['clientY'])
            
            # Calculate curvature using the three points
            curvature = self._point_curvature(p1, p2, p3)
            curvatures.append(curvature)
        
        return np.mean(curvatures) if curvatures else 0.0
    
    def _point_curvature(self, p1: Tuple[float, float], p2: Tuple[float, float], p3: Tuple[float, float]) -> float:
        """Calculate curvature at a point given three consecutive points"""
        # Vector from p1 to p2
        v1 = (p2[0] - p1[0], p2[1] - p1[1])
        # Vector from p2 to p3
        v2 = (p3[0] - p2[0], p3[1] - p2[1])
        
        # Cross product magnitude
        cross_product = abs(v1[0] * v2[1] - v1[1] * v2[0])
        
        # Magnitudes
        mag1 = math.sqrt(v1[0]**2 + v1[1]**2)
        mag2 = math.sqrt(v2[0]**2 + v2[1]**2)
        
        if mag1 > 0 and mag2 > 0:
            return cross_product / (mag1 * mag2)
        return 0.0
    
    def _calculate_jitter(self, velocities: List[float]) -> float:
        """Calculate movement jitter (velocity variance)"""
        return np.var(velocities) if len(velocities) > 1 else 0.0
    
    def _calculate_path_straightness(self, move_events: pd.DataFrame) -> float:
        """Calculate path straightness ratio"""
        if len(move_events) < 2:
            return 1.0
        
        # Direct distance from start to end
        start = move_events.iloc[0]
        end = move_events.iloc[-1]
        direct_distance = math.sqrt((end['clientX'] - start['clientX'])**2 + 
                                  (end['clientY'] - start['clientY'])**2)
        
        # Total path length
        total_distance = 0
        for i in range(1, len(move_events)):
            prev = move_events.iloc[i-1]
            curr = move_events.iloc[i]
            total_distance += math.sqrt((curr['clientX'] - prev['clientX'])**2 + 
                                      (curr['clientY'] - prev['clientY'])**2)
        
        if total_distance > 0:
            return direct_distance / total_distance
        return 1.0
    
    def _analyze_pauses(self, move_events: pd.DataFrame) -> Tuple[int, float]:
        """Analyze movement pauses"""
        if len(move_events) < 2:
            return 0, 0.0
        
        pauses = []
        threshold = 100  # milliseconds
        
        for i in range(1, len(move_events)):
            time_diff = (move_events.iloc[i]['timestamp'] - 
                        move_events.iloc[i-1]['timestamp']).total_seconds() * 1000
            if time_diff > threshold:
                pauses.append(time_diff)
        
        return len(pauses), np.mean(pauses) if pauses else 0.0
    
    def _count_double_clicks(self, df: pd.DataFrame) -> int:
        """Count double-click events"""
        click_events = df[df['type'] == 'click'].sort_values('timestamp')
        double_clicks = 0
        threshold = 500  # milliseconds
        
        for i in range(1, len(click_events)):
            time_diff = (click_events.iloc[i]['timestamp'] - 
                        click_events.iloc[i-1]['timestamp']).total_seconds() * 1000
            if time_diff < threshold:
                double_clicks += 1
        
        return double_clicks
    
    def _calculate_click_duration(self, df: pd.DataFrame) -> float:
        """Calculate average click duration (mousedown to mouseup)"""
        mousedown_events = df[df['type'] == 'mousedown']
        mouseup_events = df[df['type'] == 'mouseup']
        
        durations = []
        for _, down_event in mousedown_events.iterrows():
            up_event = mouseup_events[mouseup_events['timestamp'] > down_event['timestamp']].head(1)
            if not up_event.empty:
                duration = (up_event.iloc[0]['timestamp'] - down_event['timestamp']).total_seconds() * 1000
                durations.append(duration)
        
        return np.mean(durations) if durations else 0.0
    
    def _calculate_scroll_speed(self, scroll_events: pd.DataFrame) -> float:
        """Calculate average scroll speed"""
        if scroll_events.empty:
            return 0.0
        
        scroll_amounts = scroll_events.get('deltaY', pd.Series()).abs()
        return np.mean(scroll_amounts) if not scroll_amounts.empty else 0.0
    
    def _calculate_scroll_direction_ratio(self, scroll_events: pd.DataFrame) -> float:
        """Calculate ratio of up vs down scrolling"""
        if scroll_events.empty:
            return 0.5
        
        up_scrolls = len(scroll_events[scroll_events.get('deltaY', 0) < 0])
        down_scrolls = len(scroll_events[scroll_events.get('deltaY', 0) > 0])
        total_scrolls = up_scrolls + down_scrolls
        
        return up_scrolls / total_scrolls if total_scrolls > 0 else 0.5
    
    def _count_drag_operations(self, df: pd.DataFrame) -> int:
        """Count drag and drop operations"""
        # Simplified drag detection based on mousedown -> mousemove -> mouseup sequence
        drag_count = 0
        in_drag = False
        
        for _, event in df.iterrows():
            if event['type'] == 'mousedown':
                in_drag = True
            elif event['type'] == 'mouseup' and in_drag:
                drag_count += 1
                in_drag = False
        
        return drag_count
    
    def _calculate_avg_drag_distance(self, df: pd.DataFrame) -> float:
        """Calculate average drag distance"""
        # Simplified implementation
        return 0.0  # Would need more sophisticated drag detection
    
    def _calculate_hover_duration(self, move_events: pd.DataFrame) -> float:
        """Calculate average hover duration"""
        if len(move_events) < 2:
            return 0.0
        
        hover_threshold = 2000  # 2 seconds
        hover_durations = []
        
        stationary_start = None
        for i in range(1, len(move_events)):
            prev = move_events.iloc[i-1]
            curr = move_events.iloc[i]
            
            # Check if mouse is stationary
            distance = math.sqrt((curr['clientX'] - prev['clientX'])**2 + 
                               (curr['clientY'] - prev['clientY'])**2)
            
            if distance < 5:  # Pixel threshold for stationary
                if stationary_start is None:
                    stationary_start = prev['timestamp']
            else:
                if stationary_start is not None:
                    hover_duration = (prev['timestamp'] - stationary_start).total_seconds() * 1000
                    if hover_duration > hover_threshold:
                        hover_durations.append(hover_duration)
                    stationary_start = None
        
        return np.mean(hover_durations) if hover_durations else 0.0
    
    def _calculate_idle_time_ratio(self, df: pd.DataFrame) -> float:
        """Calculate ratio of idle time to total session time"""
        if len(df) < 2:
            return 0.0
        
        total_time = (df.iloc[-1]['timestamp'] - df.iloc[0]['timestamp']).total_seconds()
        if total_time <= 0:
            return 0.0
        
        # Calculate gaps between events
        idle_threshold = 5  # seconds
        idle_time = 0
        
        for i in range(1, len(df)):
            time_gap = (df.iloc[i]['timestamp'] - df.iloc[i-1]['timestamp']).total_seconds()
            if time_gap > idle_threshold:
                idle_time += time_gap
        
        return idle_time / total_time
    
    def _calculate_angle_entropy(self, angles: List[float]) -> float:
        """Calculate entropy of movement angles"""
        if not angles:
            return 0.0
        
        # Discretize angles into bins
        bins = 16  # 22.5-degree bins
        hist, _ = np.histogram(angles, bins=bins, range=(-math.pi, math.pi))
        
        # Calculate entropy
        probabilities = hist / np.sum(hist)
        probabilities = probabilities[probabilities > 0]  # Remove zero probabilities
        
        if len(probabilities) <= 1:
            return 0.0
        
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy