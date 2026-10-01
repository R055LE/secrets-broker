package adminweb

import (
	"context"
	"testing"

	"github.com/R055LE/secrets-broker/internal/admin"
)

type recordLogger struct {
	start  admin.MutationStart
	finish admin.MutationFinish
}

func (l *recordLogger) Start(_ context.Context, record admin.MutationStart) (string, error) {
	l.start = record
	return "operation-id", nil
}

func (l *recordLogger) Finish(_ context.Context, id string, record admin.MutationFinish) error {
	if id != "operation-id" {
		panic("correlation ID changed")
	}
	l.finish = record
	return nil
}

func TestActorLoggerPreservesUIDAndAttributesBothEvents(t *testing.T) {
	records := &recordLogger{}
	logger := actorLogger{logger: records, login: testConfig.Login}
	id, err := logger.Start(context.Background(), admin.MutationStart{ActorUID: 0, ActorLogin: "forged", Operation: "check_project_access"})
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Finish(context.Background(), id, admin.MutationFinish{ActorLogin: "forged", Outcome: "accessible"}); err != nil {
		t.Fatal(err)
	}
	if records.start.ActorUID != 0 || records.start.ActorLogin != testConfig.Login || records.finish.ActorLogin != testConfig.Login {
		t.Fatalf("attribution lost: %#v %#v", records.start, records.finish)
	}
}
