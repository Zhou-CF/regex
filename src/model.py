from openai import OpenAI
from dotenv import load_dotenv
import os

# 加载.env变量
load_dotenv()

class LLMClient:
    def __init__(self, temperature=0.7, api_key=None, base_url=None, model=None):
        if api_key and base_url and model:
            self.client = OpenAI(api_key=api_key, base_url=base_url)
            self.model = model
        else:
            self.client = OpenAI(
                api_key=os.getenv('DS_API_KEY'),
                base_url=os.getenv('DS_BASE_URL') 
            )
            self.model = os.getenv('DS_CHAT_MODEL')
        self.temperature = temperature
        self.history = []  # 用于存储上下文历史信息
        self.set_history = False  # 初始化历史记录为空

    def send_messages(self, messages):
        if not self.set_history:
            self.clear_history()
        if not isinstance(messages, list):
            messages = [self.format_messages(messages)]
        
        # 更新历史记录
        self.history.extend(messages)

        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.history,
            temperature=self.temperature,
        )
        
        # 将响应添加到历史记录
        self.history.append(response.choices[0].message)
        return response.choices[0].message

    def send_messages_with_json(self, messages):
        if not self.set_history:
            self.clear_history()
        if not isinstance(messages, list):
            messages = [self.format_messages(messages)]
        
        # 更新历史记录
        self.history.extend(messages)

        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.history,
            temperature=self.temperature,
            response_format={
                'type': 'json_object'
            }
        )
        
        # 将响应添加到历史记录
        self.history.append(response.choices[0].message)
        return response.choices[0].message

    def send_messages_stream(self, messages):
        if not self.set_history:
            self.clear_history()
        if not isinstance(messages, list):
            messages = [self.format_messages(messages)]
        
        # 更新历史记录
        self.history.extend(messages)

        # 使用流式输出
        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.history,
            temperature=self.temperature,
            stream=True  # 启用流式输出
        )
        
        # 逐步处理流式响应
        for chunk in response:
            if 'choices' in chunk:
                yield chunk['choices'][0]['delta']['content']  # 逐步返回内容

    def format_messages(self, content, role="user"):
        return {
            "role": role,
            "content": content
        }

    def clear_history(self):
        """清空上下文历史信息"""
        self.history = []
