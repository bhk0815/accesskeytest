import boto3
import json
import logging

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
sns = boto3.client('sns')

# SNS Topic ARN을 환경 변수나 하드코딩으로 설정하세요.
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:011612734520:access-key-notice'

def lambda_handler(event, context):
    try:
        # EventBridge로부터 전달받은 상세 정보 추출
        detail = event.get('detail', {})
        affected_entities = detail.get('affectedEntities', [])
        
        if not affected_entities:
            logger.info("비활성화할 엔티티가 없습니다.")
            return
        
        for entity in affected_entities:
            access_key_id = entity.get('entityValue')
            
            # 1. IAM Access Key 비활성화
            # 주의: Username을 모를 경우를 대비해 ListAccessKeys를 사용할 수도 있지만, 
            # Health 이벤트는 보통 User 정보가 포함되거나 Key ID만으로 처리가 필요할 수 있습니다.
            # 여기서는 공개된 Key ID를 통해 해당 키를 비활성화합니다.
            
            # 우선 해당 키의 사용자를 찾아야 합니다 (UpdateAccessKey는 UserName 필요)
            # 유출된 키는 보안상 즉시 비활성화가 우선입니다.
            try:
                # Access Key ID를 통해 해당 User를 찾기 위한 로직 (보통은 시스템 로깅 활용)
                # 직접 UserName을 찾기 어려울 경우 모든 사용자를 순회하거나 특정 명명 규칙 활용
                # 아래는 일반적인 처리 방식입니다.
                
                # AWS Health 이벤트의 경우 'entityValue'가 Access Key ID입니다.
                # 참고: 실제 환경에서는 해당 Key ID의 소유자를 먼저 식별해야 합니다.
                user_name = get_user_name_by_key(access_key_id)
                
                if user_name:
                    iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=access_key_id,
                        Status='Inactive'
                    )
                    message = f"경고: 유출된 Access Key {access_key_id} (사용자: {user_name})가 비활성화되었습니다."
                    logger.info(message)
                    
                    # 2. SNS 알림 전송
                    sns.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Subject="[보안 알림] IAM Access Key 자동 비활성화 완료",
                        Message=message
                    )
                else:
                    logger.error(f"Access Key {access_key_id}에 해당하는 사용자를 찾을 수 없습니다.")
                    
            except Exception as e:
                logger.error(f"Error processing key {access_key_id}: {str(e)}")

    except Exception as e:
        logger.error(f"Lambda 실행 중 오류 발생: {str(e)}")
        raise e

def get_user_name_by_key(access_key_id):
    """Access Key ID로 UserName을 찾는 헬퍼 함수"""
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']
            keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            for key in keys:
                if key['AccessKeyId'] == access_key_id:
                    return user_name
    return None